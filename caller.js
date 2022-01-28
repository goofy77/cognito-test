var AmazonCognitoIdentity = require('amazon-cognito-identity-js');

const authenticationData = {
    Username: '',
    Password: '',
};
const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(
    authenticationData
);
const poolData = {
    UserPoolId: '', // Your user pool id here
    ClientId: '', // Your client id here
};
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
const userData = {
    Username: 'mateusz',
    Pool: userPool,
};
const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
cognitoUser.authenticateUser(authenticationDetails, {
    onSuccess: function(result) {
        const accessToken = result.getAccessToken().getJwtToken();
        console.log(accessToken)
        const s = result.getAccessToken().getJwtToken();
    },

    newPasswordRequired: function(userAttributes, requiredAttributes) {
        // User was signed up by an admin and must provide new
        // password and required attributes, if any, to complete
        // authentication.
        console.log({userAttributes, requiredAttributes})
        // the api doesn't accept this field back
        delete userAttributes.email_verified;
        cognitoUser.completeNewPasswordChallenge(authenticationData.Password, userAttributes)
    },

    onFailure: function(err) {
        console.log({err})
    },

});