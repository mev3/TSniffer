contract Token {
  mapping(address => uint) public balanceOf;
  address public owner = tx.origin;
  // mapping(address => mapping(uint256 => uint256)) private _balance;


function changeOwner (address _owner) public returns(bool)
  {
    if (msg.sender == owner){
      owner = msg.sender;
    }
  }
  function transfer(address _to, uint _value) public returns (bool) {

      balanceOf[msg.sender] -= _value;
      balanceOf[_to] += (_value - 10);
      return true;
  }
}
