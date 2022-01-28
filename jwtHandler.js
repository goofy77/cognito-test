const jwt = require('jsonwebtoken');
const axios = require('axios')
const jwkToPem = require('jwk-to-pem');

let jwks = undefined
async function verify(token) {
    const decoded = jwt.decode(token, { complete: true });
    if (!jwks) {
        jwks = {}
        const { data } = await axios.get("https://cognito-idp.{region}.amazonaws.com/{cognitoPoolID}/.well-known/jwks.json")
        data.keys.forEach(jwk => {
            jwks[jwk.kid] = jwk;
        })
    }
    const pem = jwkToPem(jwks[decoded.header.kid]);
    return await check(token, pem)
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
