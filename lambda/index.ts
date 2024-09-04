import {promisify} from 'util';
import * as Axios from 'axios';
import jsonwebtoken from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';

export interface ClaimVerifyRequest {
  readonly authorizationToken?: string;
  readonly methodArn: string;
}

export interface ClaimVerifyResult {
  readonly userName: string;
  readonly clientId: string;
  readonly isValid: boolean;
  readonly error?: any;
}

interface TokenHeader {
  kid: string;
  alg: string;
}
interface PublicKey {
  alg: string;
  e: string;
  kid: string;
  kty: string;
  n: string;
  use: string;
}
interface PublicKeyMeta {
  instance: PublicKey;
  pem: string;
}

interface PublicKeys {
  keys: PublicKey[];
}

interface MapOfKidToPublicKey {
  [key: string]: PublicKeyMeta;
}

interface Claim {
  token_use: string;
  auth_time: number;
  iss: string;
  exp: number;
  username: string;
  client_id: string;
}

const cognitoPoolId = process.env.COGNITO_POOL_ID || '';
if (!cognitoPoolId) {
  throw new Error('env var required for cognito pool');
}
const cognitoIssuer = `https://cognito-idp.us-west-1.amazonaws.com/${cognitoPoolId}`;

let cacheKeys: MapOfKidToPublicKey | undefined;
const getPublicKeys = async (): Promise<MapOfKidToPublicKey> => {
  if (!cacheKeys) {
    const url = `${cognitoIssuer}/.well-known/jwks.json`;
    const publicKeys = await Axios.default.get<PublicKeys>(url);
    cacheKeys = publicKeys.data.keys.reduce((agg: any, current: any) => {
      const pem = jwkToPem(current);
      agg[current.kid] = {instance: current, pem};
      return agg;
    }, {} as MapOfKidToPublicKey);
    return cacheKeys as any;
  } else {
    return cacheKeys;
  }
};

const verifyPromised = promisify(jsonwebtoken.verify);

const generatePolicy = function(principalId: string, effect: string, resource: string) {
  var authResponse = {
    principalId: '',
  };
  
  authResponse.principalId = principalId;
  if (effect && resource) {
      var policyDocument = {
        Version: '',
        Statement: [] as any[],
      };
      policyDocument.Version = '2012-10-17'; 
      policyDocument.Statement = [] as any[];
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
}

const handler = async (request: ClaimVerifyRequest, context: any, callback: any): Promise<any> => {
  let result: ClaimVerifyResult;
  try {
    console.log(`user claim verify invoked for ${JSON.stringify(request)}`);
    const token = request.authorizationToken;
    const tokenSections = (token || '').split('.');
    if (tokenSections.length < 2) {
      throw new Error('requested token is invalid');
    }
    const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
    const header = JSON.parse(headerJSON) as TokenHeader;
    const keys = await getPublicKeys();
    const key = keys[header.kid];
    if (key === undefined) {
      throw new Error('claim made for unknown kid');
    }
    // @ts-ignore
    const claim = await verifyPromised(token, key.pem) as unknown as Claim;
    const currentSeconds = Math.floor( (new Date()).valueOf() / 1000);
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
    result = {userName: claim.username, clientId: claim.client_id, isValid: true};
  } catch (error) {
    result = {userName: '', clientId: '', error, isValid: false};
  }

  if (result.userName) {
    callback(null, generatePolicy('user', 'Allow', request.methodArn));
  } else {
    callback(null, generatePolicy('user', 'Deny', request.methodArn));
  }
};

export {handler};