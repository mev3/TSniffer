contract Token {
  mapping(address => uint) public balanceOf;
  mapping(address => uint) public balanceOf2;
  mapping(address => uint) public balanceOf3;
  mapping(address => uint) public balanceOf4;
  uint public totalSupply;
//  address public a;

// function changeA(address _a) public returns(bool){
//    if (msg.sender == a)
//    {
//        a = _a;
//    }
//  }
  function transfer(address _to, uint _value) public returns (bool) {
//    if (msg.sender == a)
//    {
      balanceOf[msg.sender] -= _value;
      balanceOf[_to] += _value;
      return true;
//    }
  }
}
