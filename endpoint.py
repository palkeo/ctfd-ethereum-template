#!/usr/bin/env python3
from flask import Flask, request, abort
from web3.auto import w3

import logging
import queue
import threading

app = Flask(__name__)

logger = app.logger

# Constructor bytecode. You could also compile solidity code from python:
# https://web3py.readthedocs.io/en/stable/contracts.html
CONTRACT_BYTECODE = "608060405234801561001057600080fd5b5060c58061001f6000396000f3fe6080604052348015600f57600080fd5b50600436106045576000357c0100000000000000000000000000000000000000000000000000000000900480639d11877014604a575b600080fd5b607360048036036020811015605e57600080fd5b81019080803590602001909291905050506075565b005b602a8114156096573373ffffffffffffffffffffffffffffffffffffffff16ff5b5056fea165627a7a7230582074abcc958736d80480501f965d4df8a204d5304da8606efd7081638dc9af85ed0029"
CONTRACT_ABI = [{"constant":False,"inputs":[{"name":"secret","type":"uint256"}],"name":"destroy","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"}]

# TODO: Maybe put that dict into a JSON file on disk? So it's persisted in
# case we need to restart the server.
challenges = {}

# Contains challenge contracts that have been created and are ready to be used
# by a new team. It is filled by a worker thread in parallel with the serving,
# so creating a new challenge is instant.
addr_queue = queue.Queue(maxsize=4)


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
    logger.info("Created new challenge for team %s: %s", team_id, challenges[team_id])

    try:
        addr = challenges[team_id]
    except KeyError:
        abort(401)

    logger.info(
        "Checking for solving of challenge at address %s for team %s", addr, team_id
    )

    if w3.eth.getCode(addr) > 2:
        abort(403)

    return "Success"


def create_contract():
    logger.info("Creating new contract...")

    Contract = w3.eth.contract(abi=CONTRACT_ABI, bytecode=CONTRACT_BYTECODE)
    tx_hash = Contract.constructor().transact()

    # Wait for the transaction to be mined.
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    addr = tx_receipt.contractAddress

    logger.info("Created new contract at addr %s", addr)
    return addr


def contract_creator():
    while True:
        addr_queue.put(create_contract())


if __name__ == "__main__":
    logger.setLevel(logging.INFO)
    contract_creator_thread = threading.Thread(target=contract_creator)
    contract_creator_thread.start()
    app.run(debug=True, threaded=True, host="127.0.0.1", port=4001)
