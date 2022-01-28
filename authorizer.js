const {verify} = require('./jwtHandler.js')

exports.handler =  async (event, context) => {
    console.log({event, context})
    const token = event.authorizationToken;
    const result = await verify(token)
    console.log({ result })
    switch (token) {
        case 'allow':
            return generatePolicy('user', 'Allow', event.methodArn);
        case 'deny':
            return generatePolicy('user', 'Deny', event.methodArn);
        case 'unauthorized':
            return generatePolicy("Unauthorized");
        default:
            return "Error: Invalid token";
    }

};

// Help function to generate an IAM policy
var generatePolicy = function(principalId, effect, resource) {
    var authResponse = {};

    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17';
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke';
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }

    // Optional output with custom properties of the String, Number or Boolean type.
    authResponse.context = {
        "stringKey": "stringval",
        "numberKey": 123,
        "booleanKey": true
    };
    return authResponse;
}