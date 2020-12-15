Daniel Adea 204999515

Design:

    The spec was a little confusing so I leaned on the TA slides as a reference.
    We first check if we got a valid message of course. If it is an arp, we
    check whether it is an arp reply or an arp response. If it s an arp reply,
    we get the arp requests associated with it and send all the packets for
    those because we finally got the information needed to send them. If it's an
    arp request, we switch the sender ip address and receiver ip address as well
    as changing the type to an arp reply and send the message back.

    On the other hand, we might get an IP packet. If we do, we have to check the
    checksum first. Then, if the ip address is the router ip address, we check
    if it is a valid icmp message. If it is, then we have to figure out if our
        destination is in the arp cache. If it isn't, we queue it but if it is,
        we send it!
        If the ip address is not the router's we do ip forwarding.

Problems:

    I had a hard time follow what needed to be executed based on the spec. A
    cohesive walkthrough would've helped and the TA discussion did that a little
    bit. I was confused about getting the structs right for the headers, but Piazza helped. 
    I also kept messing up the checksum, but just brute forced that by putting
    it in different places until it worked. The hardest part was keeping track
    of when I had the right address and when I had to reassign them. I had to
    refer to piazza and the discusssions a lot for this.
