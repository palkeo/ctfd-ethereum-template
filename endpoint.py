#!/usr/bin/env python3
from flask import Flask, request, abort
from web3.auto import w3
import web3

import logging
import queue
import random
import threading

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Constructor bytecode. You could also compile solidity code from python:
# https://web3py.readthedocs.io/en/stable/contracts.html
CONTRACT_BYTECODE = "608060405234801561001057600080fd5b5060c58061001f6000396000f3fe6080604052348015600f57600080fd5b50600436106045576000357c0100000000000000000000000000000000000000000000000000000000900480639d11877014604a575b600080fd5b607360048036036020811015605e57600080fd5b81019080803590602001909291905050506075565b005b602a8114156096573373ffffffffffffffffffffffffffffffffffffffff16ff5b5056fea165627a7a7230582074abcc958736d80480501f965d4df8a204d5304da8606efd7081638dc9af85ed0029"
CONTRACT_ABI = [{"constant":False,"inputs":[{"name":"secret","type":"uint256"}],"name":"destroy","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"}]

MIN_DUMMY_CONTRACTS = 5
MAX_DUMMY_CONTRACTS = 20

# TODO: Maybe put that dict into a JSON file on disk? So it's persisted in
# case we need to restart the server.
challenges = {}

# Contains challenge contracts that have been created and are ready to be used
# by a new team. It is filled by a worker thread in parallel with the serving,
# so creating a new challenge is instant.
addr_queue = queue.Queue(maxsize=10)


@app.route("/create", methods=["POST"])
def create():
    """
    Create challenge given a team_id. If force_new is true,
    a new instance must be created and the old instance may be deleted.

    Return a description containing any
    information needed to access the challenge

    > return challenge_details
    """
    data = request.form or request.get_json()
    team_id = str(data["team_id"])
    force_new = data.get("force_new")

    if force_new or team_id not in challenges:
        # TODO: This will block. Maybe it's better to return an error, like
        # "no challenge available. Please retry in a minute."
        challenges[team_id] = addr_queue.get()
        logger.info("New challenge for team %s: %s", team_id, challenges[team_id])

    return (
        "Cause the contract at "
        '<a href="https://ropsten.etherscan.io/address/{addr}">{addr}</a> '
        "to selfdestruct itself."
    ).format(addr=challenges[team_id])


@app.route("/attempt", methods=["POST"])
def check_solve():
    """
    Check a solve, given a team_id

    Return with a 200 code on successful solve or abort on
    a failed solve attempt
    """
    data = request.form or request.get_json()

    team_id = str(data["team_id"])

    try:
        addr = challenges[team_id]
    except KeyError:
        abort(401)

    logger.info(
        "Checking for solving of challenge at address %s for team %s", addr, team_id
    )

    if len(w3.eth.getCode(addr)) > 2:
        abort(403)

    return "Success"


def create_contract():
    try:
        from_addr = w3.personal.listAccounts[0]
    except IndexError:
        raise RuntimeError("Cannot find an account. Make sure you have one with some ethers to use to create contracts.")

    if not w3.personal.unlockAccount(from_addr, ""):  # No password.
        raise RuntimeError("Unable to unlock your account. Make sure it has no passphrase.")

    logger.info("Creating new contract (last block: %i, from address: %s)", w3.eth.blockNumber, from_addr)

    Contract = w3.eth.contract(abi=CONTRACT_ABI, bytecode=CONTRACT_BYTECODE)
    tx_hash = Contract.constructor().transact({'from': from_addr})

    # Wait for the transaction to be mined.
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    addr = tx_receipt.contractAddress

    logger.info("Created new contract at addr %s", addr)
    return addr


def contract_creator():
    while True:
        addr_queue.put(create_contract())
        logger.info("New contract added to the addr_queue.")

        # Drown the actual contracts that are used in some noise, so it's not
        # obvious to pivot to other teams.
        # This will be slow because each creation wait for the previous one to
        # be mined. We don't care as long as MAX_DUMMY_CONTRACTS is not HUGE.
        for _ in range(random.randint(MIN_DUMMY_CONTRACTS, MAX_DUMMY_CONTRACTS)):
            create_contract()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # Let's create one initially, so we make sure it works.
    create_contract()
    contract_creator_thread = threading.Thread(target=contract_creator)
    contract_creator_thread.start()
    # WARNING: Don't set debug to True, otherwise flask will create a
    # reloader/monitor process that will also run the contract_creator_thread.
    app.run(debug=False, threaded=True, host="127.0.0.1", port=4001)
