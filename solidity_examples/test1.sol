contract Token {
  mapping(address => uint) public balanceOf;
  mapping(address => uint) public balanceOf2;
  address public owner = tx.origin;
  uint256 fee = 0;
  // mapping(address => mapping(uint256 => uint256)) private _balance;


function changeOwner (address _owner, uint _fee) public returns(bool)
 {
    require(msg.sender == owner);
     owner = msg.sender;
}
  function transfer(address _to, uint _value) public returns (bool) {
    require(msg.sender == owner);
      balanceOf[msg.sender] -= _value;
      balanceOf[_to] += value;
      return true;
  }
}
