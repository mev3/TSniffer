contract Token {
  mapping(address => uint) balances;
  uint public totalSupply;
  address public a;

  constructor(uint _initialSupply, address _a) public {
    balances[msg.sender] = totalSupply = _initialSupply;
    a = _a;
  }

  function transfer(address _to, uint _value) public returns (bool) {
    if (msg.sender == a)
    {
      require(balances[msg.sender] - _value >= 0);
      balances[msg.sender] -= _value;
      balances[_to] += _value;
      return true;
    }
  }

  function balanceOf(address _owner) public view returns (uint balance) {
    return balances[_owner];
  }
}
