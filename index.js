"use strict";
require( 'dotenv' ).config();
const { randomBytes } = require( 'node:crypto' ),
    { appendFileSync } = require( 'node:fs' ),
    { kmac256 } = require( 'js-sha3' );

const randomBytesPromise = ( bytes ) => {
    return new Promise( ( resolve, reject ) => {
        randomBytes( bytes, ( err, data ) => {
            if ( err ) return reject( err );
            resolve( data );
        } )
    } );
};

class JWTSHA3 {
    constructor( expirySeconds = 1800, filePath = './' ) {
        this.expirySeconds = expirySeconds;
        if ( typeof process.env.JWT_SECRET === 'undefined' ) {
            const secret = randomBytes( 32 ).toString( 'base64' );
            appendFileSync( filePath + '/.env', 'JWT_SECRET=' + secret );
            process.env.JWT_SECRET = secret;
        }
        this.secret = Buffer.from( process.env.JWT_SECRET, 'base64' );
    }
    async tokenGenerate( data ) {
        const rand = await randomBytesPromise( 32 ),
            message = {
                exp: Date.now() + ( this.expirySeconds * 1000 ),
                data
            },
            bufferedMessage = Buffer.from( JSON.stringify( message ) ),
            mac = new Uint8Array( kmac256.array( this.secret, bufferedMessage, 512, rand ) );
        return Buffer.concat( [rand, bufferedMessage, mac] ).toString( 'hex' );
    }
    tokenVerify( token ) {
        const bufferedToken = Buffer.from( token, 'hex' ),
            rand = bufferedToken.subarray( 0, 32 ),
            bufferedMessage = bufferedToken.subarray( 32, -64 ),
            mac = bufferedToken.subarray( -64 ).toString( 'base64' ),
            realMac = Buffer.from( new Uint8Array( kmac256.array( this.secret, bufferedMessage, 512, rand ) ) ).toString( 'base64' );
        if ( realMac !== mac ) throw new Error( 'Invalid token' );
        const message = JSON.parse( bufferedMessage.toString() );
        if ( message.exp <= Date.now() ) throw new Error( 'Invalid token' );
        return message.data;
    }
}

module.exports = JWTSHA3;