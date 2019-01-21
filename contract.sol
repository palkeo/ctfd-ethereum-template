contract Contract {
    function destroy(uint secret) public {
        if (secret == 42) {
            selfdestruct(msg.sender);
        }
    }
}
