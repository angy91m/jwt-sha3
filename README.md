# jwt-sha3
Easy token generator with KMAC256

Usage:
```javascript
    const JWTSHA3 = require( 'jwt-sha3' ),
        generator = new JWTSHA3( 1800, './' );      // Default expiration in seconds and path where to generate .env file with permanent secret key
    let message = 'Ciao!';                          // Any object


    const token = await generator.tokenGenerate( message );
    message = generator.tokenVerify( token );
```