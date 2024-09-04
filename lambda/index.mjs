var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { promisify } from 'util';
import * as Axios from 'axios';
import jsonwebtoken from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';
const cognitoPoolId = process.env.COGNITO_POOL_ID || '';
if (!cognitoPoolId) {
    throw new Error('env var required for cognito pool');
}
const cognitoIssuer = `https://cognito-idp.us-west-1.amazonaws.com/${cognitoPoolId}`;
let cacheKeys;
const getPublicKeys = () => __awaiter(void 0, void 0, void 0, function* () {
    if (!cacheKeys) {
        const url = `${cognitoIssuer}/.well-known/jwks.json`;
        const publicKeys = yield Axios.default.get(url);
        cacheKeys = publicKeys.data.keys.reduce((agg, current) => {
            const pem = jwkToPem(current);
            agg[current.kid] = { instance: current, pem };
            return agg;
        }, {});
        return cacheKeys;
    }
    else {
        return cacheKeys;
    }
});
const verifyPromised = promisify(jsonwebtoken.verify);
const generatePolicy = function (principalId, effect, resource) {
    var authResponse = {
        principalId: '',
    };
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {
            Version: '',
            Statement: [],
        };
        policyDocument.Version = '2012-10-17';
        policyDocument.Statement = [];
        var statementOne = {
            Action: '',
            Effect: effect,
            Resource: resource,
        };
        statementOne.Action = 'execute-api:Invoke';
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement.push(statementOne);
        // @ts-ignore
        authResponse.policyDocument = policyDocument;
    }
    return authResponse;
};
const handler = (request, context, callback) => __awaiter(void 0, void 0, void 0, function* () {
    let result;
    try {
        console.log(`user claim verify invoked for ${JSON.stringify(request)}`);
        const token = request.authorizationToken;
        const tokenSections = (token || '').split('.');
        if (tokenSections.length < 2) {
            throw new Error('requested token is invalid');
        }
        const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
        const header = JSON.parse(headerJSON);
        const keys = yield getPublicKeys();
        const key = keys[header.kid];
        if (key === undefined) {
            throw new Error('claim made for unknown kid');
        }
        // @ts-ignore
        const claim = yield verifyPromised(token, key.pem);
        const currentSeconds = Math.floor((new Date()).valueOf() / 1000);
        if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
            throw new Error('claim is expired or invalid');
        }
        if (claim.iss !== cognitoIssuer) {
            throw new Error('claim issuer is invalid');
        }
        if (claim.token_use !== 'access') {
            throw new Error('claim use is not access');
        }
        console.log(`claim confirmed for ${claim.username}`);
        result = { userName: claim.username, clientId: claim.client_id, isValid: true };
    }
    catch (error) {
        result = { userName: '', clientId: '', error, isValid: false };
    }
    if (result.userName) {
        callback(null, generatePolicy('user', 'Allow', request.methodArn));
    }
    else {
        callback(null, generatePolicy('user', 'Deny', request.methodArn));
    }
});
export { handler };
