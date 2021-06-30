namespace Cryptography.Library.Test.Factories
{
  public static class RsaKeyFactory
  {
    public static string Create1024PrivateKey() => "<RSAKeyValue><Modulus>t5/shldX02+zmmE6Gk8GlWmk+9xGWsz25nbw1as3BQc8XSfqQDG0k6bAhtuEM4clKVQXtFklyNCdPz3NBkYUsS/HYvgZVO1MTp8YfkzohwudyIsAMxfZxLLwUymIXoIaHmgV3tCDvVCm1sYIgXOouW82OeZg/ysaqEVzyqktIxk=</Modulus><Exponent>AQAB</Exponent><P>x7RDEaP4+Ra6HI2dv/CxBfJbT6OyugO8gdh8WQdN8eD7X1BYKldovgAw1Qil8jNCvyo3ZjpKhqDclrEz4i3xTw==</P><Q>62NIGktpeckzbXm/GZG8fTq+a3/K9q/D8/5poIXlCsw/1iBUDDhwbpzGm2xAKC97HMAnbZBL3ExipPXg2Ez7Fw==</Q><DP>XFLv9sXRooZpQC4QUd4aWN90a1sIk4qKqZTF1/rShBI45BWmzNxgJga8jKBU56XfI7WGqxIjxh20HU6K5/PJbQ==</DP><DQ>AaJb0srpPY43DDCHMh8/5sKspcRqXVIVEzGV/CZR08RdQRhSXQ9bQHlYK6YRv/WsbiOrYmhZDnt9R9XpLLdEGw==</DQ><InverseQ>uEjXH17WYy0l7dxKIAoP3/txRdY7cz0dv9zHlF7wLh3qYWc9F/27MGeyrdVG4gnSg8Ohdz1rkiBsFZhlf4oo6w==</InverseQ><D>d6/Avovdzg4n1f97nLxXwTm79QJNxU+FuxBZyBuyYA+oU9v5fuAnIHp3US9yCxgSq86JKN9Wln8Lj7YblfRF9WBjSVhlGwya6eiOYuxR52CcegU4ifDy61Wb5iR5JZPxNmHDdakNZG3tFWo1LPPSfrkyn1eNPD0GBEoD6a3s8WU=</D></RSAKeyValue>";
    public static string Create1024PublicKey() => "<RSAKeyValue><Modulus>t5/shldX02+zmmE6Gk8GlWmk+9xGWsz25nbw1as3BQc8XSfqQDG0k6bAhtuEM4clKVQXtFklyNCdPz3NBkYUsS/HYvgZVO1MTp8YfkzohwudyIsAMxfZxLLwUymIXoIaHmgV3tCDvVCm1sYIgXOouW82OeZg/ysaqEVzyqktIxk=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
  }
}
