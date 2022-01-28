const jwt = require('jsonwebtoken');
const axios = require('axios')
const jwkToPem = require('jwk-to-pem');

let jwks = undefined

async function verify(token) {
    const decoded = jwt.decode(token, { complete: true });
    if (!jwks) {
        jwks = {}
        const { data } = await axios.get("https://cognito-idp.eu-central-1.amazonaws.com/{cognitoPoolId}/.well-known/jwks.json")
        data.keys.forEach(jwk => {
            jwks[jwk.kid] = jwk;
        })
    }
    try {
        const pem = jwkToPem(jwks[decoded.header.kid]);
        const result = await check(token, pem)
        return result
    } catch (e) {
        console.log(e)
    }
    return jwt.decode(token, { complete: true });
}

async function check(token, pem) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, pem, { algorithms: ['RS256'] }, (err, decodedToken) => {
            if (err) {
                return reject(err);
            } else {
                return resolve(decodedToken)
            }
        });
    })
}

module.exports = { verify }
