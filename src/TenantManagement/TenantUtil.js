/* eslint-disable no-use-before-define */
const AWS = require('aws-sdk');
const requestPromise = require('request-promise');

// Declare dependencies
const PASSWORD_MIN_LENGTH = 8;
const UNUSED_ACCOUNT_VALIDITY_DAYS = 365;

class TenantUtil {
    constructor(serviceLocator) {
        this.commons = serviceLocator.get('commons');
        this.config = serviceLocator.get('config');
        this.logger = serviceLocator.get('logger');
        this.cognito = new AWS.CognitoIdentityServiceProvider({
            apiVersion: '2016-04-18'
        });
    }

    /**
     * Create a new User Pool for a new tenant
     *
     * @param {String} tenantId The ID of the new tenant
     */
    async createUserPool(tenantId) {
        // Invite Message:
        // eslint-disable-next-line max-len
        const credentialMessage = 'Username: {username} <br><br>Password: {####}';
        const userInvitationMessage = `Welcome. <br><br>${credentialMessage}`;
        const emailVerificationMessage = 'Please use <b>{####}</b> code to verify your email address.';
        const emailSubject = 'Email Verification';
        const smsMessage = `Welcome. <br><br>${credentialMessage}`;

        // init JSON structure with pool settings
        const params = {
            PoolName: tenantId, /* required */
            AdminCreateUserConfig: {
                AllowAdminCreateUserOnly: false,
                InviteMessageTemplate: {
                    EmailSubject: emailSubject,
                    EmailMessage: userInvitationMessage,
                    SMSMessage: smsMessage
                },
                UnusedAccountValidityDays: UNUSED_ACCOUNT_VALIDITY_DAYS
            },
            AliasAttributes: [
                'email',
                'phone_number',
                'preferred_username'
            ],
            AutoVerifiedAttributes: [
                'email'
                // , 'phone_number'
            ],
            MfaConfiguration: 'OFF',
            Policies: {
                PasswordPolicy: {
                    MinimumLength: PASSWORD_MIN_LENGTH,
                    RequireLowercase: true,
                    RequireNumbers: true,
                    RequireSymbols: true,
                    RequireUppercase: true
                }
            },
            Schema: [
                {
                    Name: "email",
                    Required: true
                },
                // {
                //     Name: "phone_number",
                //     Required: true
                // },
                {
                    AttributeDataType: 'String',
                    DeveloperOnlyAttribute: false,
                    Mutable: true,
                    Name: 'tenantId',
                    NumberAttributeConstraints: {
                        MaxValue: '256',
                        MinValue: '1'
                    },
                    Required: false,
                    StringAttributeConstraints: {
                        MaxLength: '256',
                        MinLength: '1'
                    }
                }
            ],
            SmsAuthenticationMessage: smsMessage,
            SmsVerificationMessage: smsMessage,
            // SmsConfiguration: {
            //     SnsCallerArn: this.config.CognitoSnsArn /* required */
            // },
            UserPoolTags: {
                tenant: tenantId
            },
            EmailVerificationMessage: emailVerificationMessage,
            EmailVerificationSubject: emailSubject,
            LambdaConfig: {
                PostConfirmation: this.config.PostConfirmationLambdaArn
            }
        };

        // create the pool
        this.logger.silly("Prepared params for createUserPool", params);
        const userPool = await this.cognito.createUserPool(params).promise();
        this.logger.silly("Created user pool", userPool);
        return userPool;
    }

    /**
     * Delete an existing User Pool for a tenant
     *
     * @param {String} userPoolId The ID of the existing tenant
     */
    async deleteUserPool(userPoolId) {
        const params = {
            UserPoolId: userPoolId
        };
        const response = await this.cognito.deleteUserPool(params).promise();
        this.logger.silly("Deleted user pool", response);
        return response;
    }

    /**
     * Create a user pool client for a new tenant
     *
     * @param {Object} poolConfig The config parameters for creating client
     * @param {String} poolConfig.clientName Name of the new user pool client
     * @param {String} poolConfig.userPoolId Id of the existing user pool
     * @param {Array} poolConfig.redirectUris Allowed redirect URLs after login
     */
    async createUserPoolClient(poolConfig) {
        // config the client parameters
        const params = {
            ClientName: poolConfig.clientName, /* required */
            UserPoolId: poolConfig.userPoolId, /* required */
            GenerateSecret: true,
            ReadAttributes: [
                'email',
                'family_name',
                'given_name',
                'phone_number',
                'preferred_username',
                'custom:tenantId'
            ],
            RefreshTokenValidity: 0,
            WriteAttributes: [
                'email',
                'family_name',
                'given_name',
                'phone_number',
                'preferred_username'
            ],
            AllowedOAuthFlows: [
                'code',
                'implicit'
            ],
            AllowedOAuthScopes: [
                'phone',
                'email',
                'openid',
                'aws.cognito.signin.user.admin',
                'profile'
            ],
            AllowedOAuthFlowsUserPoolClient: true,
            CallbackURLs: poolConfig.redirectUris,
            SupportedIdentityProviders: [
                'COGNITO'
            ],
            ExplicitAuthFlows: [
                'ADMIN_NO_SRP_AUTH',
                'USER_PASSWORD_AUTH'
            ]
        };

        // create the Cognito client
        const userPoolClient = await this.cognito.createUserPoolClient(params).promise();
        this.logger.silly("Created user pool client", userPoolClient);
        return userPoolClient;
    }

    /**
     * Update a user pool client for existing tenant
     *
     * @param {Object} poolConfig The config parameters for updating client
     * @param {String} poolConfig.clientId Id of the exitng user pool client
     * @param {String} poolConfig.userPoolId Id of the existing user pool
     * @param {Array} poolConfig.redirectUris Allowed redirect URLs after login
     */
    async updateUserPoolClient(poolConfig) {
        // config the client parameters
        const params = {
            ClientId: poolConfig.clientId,
            UserPoolId: poolConfig.userPoolId,
            CallbackURLs: poolConfig.redirectUris
        };

        // get existing Cognito client to get current properties
        let userPoolClient = await this.getUserPoolClient(poolConfig);
        delete userPoolClient.UserPoolClient.ClientSecret;
        delete userPoolClient.UserPoolClient.LastModifiedDate;
        delete userPoolClient.UserPoolClient.CreationDate;

        // update the Cognito client using existing client properties
        userPoolClient = await this.cognito.updateUserPoolClient(Object.assign(userPoolClient.UserPoolClient, params)).promise();
        this.logger.silly("Updated user pool client", userPoolClient);
        return userPoolClient;
    }

    /**
     * Get a user pool client for existing tenant
     *
     * @param {Object} poolConfig The config parameters for updating client
     * @param {String} poolConfig.clientId Id of the exitng user pool client
     * @param {String} poolConfig.userPoolId Id of the existing user pool
     */
    async getUserPoolClient(poolConfig) {
        // config the client parameters
        const params = {
            ClientId: poolConfig.clientId,
            UserPoolId: poolConfig.userPoolId
        };

        // get the Cognito client
        const userPoolClient = await this.cognito.describeUserPoolClient(params).promise();
        this.logger.silly("Got user pool client", userPoolClient);
        return userPoolClient;
    }

    /**
     * Create a user pool domain for a user pool
     *
     * @param {String} domain Domain prefix of the new user pool domain
     * @param {String} userPoolId Id of the existing user pool
     */
    async createUserPoolDomain(domain, userPoolId) {
        const params = {
            Domain: domain,
            UserPoolId: userPoolId
        };

        // create the Cognito user pool domain
        const userPoolDomain = await this.cognito.createUserPoolDomain(params).promise();
        this.logger.silly("Created user pool domain", userPoolDomain);
        return userPoolDomain;
    }

    /**
     * Create a user pool domain for a user pool
     *
     * @param {String} domain Domain prefix of the new user pool domain
     * @param {String} userPoolId Id of the existing user pool
     */
    async deleteUserPoolDomain(domain, userPoolId) {
        const params = {
            Domain: domain,
            UserPoolId: userPoolId
        };

        // delete the Cognito user pool domain
        const userPoolDomain = await this.cognito.deleteUserPoolDomain(params).promise();
        this.logger.silly("Deleted user pool domain", userPoolDomain);
        return userPoolDomain;
    }

    /**
     * Get user pool signing certificate
     *
     * @param {String} userPoolId Id of the existing user pool
     */
    async getUserPoolCertificate(userPoolId) {
        const params = {
            UserPoolId: userPoolId
        };
        const certPreText = '-----BEGIN CERTIFICATE-----\n';
        const certPostText = '\n-----END CERTIFICATE-----';
        const certificateObj = await this.cognito.getSigningCertificate(params).promise();
        const certificate = certPreText + certificateObj.Certificate + certPostText;
        this.logger.silly("Signing certificate", certificate);
        return certificate;
    }

    /**
     * Create a user pool domain for a user pool
     *
     * @param {Object} groupConfig The config parameters to creae new group
     * @param {String} poolConfig.name Name of the new group
     * @param {String} poolConfig.description Description of the new group
     * @param {String} poolConfig.precedence Precedence of the new group
     * @param {String} poolConfig.roleArn Role ARN of the new group
     * @param {String} userPoolId Id of the existing user pool
     */
    async createUserPoolGroup(groupConfig, userPoolId) {
        const params = {
            GroupName: groupConfig.name,
            Description: groupConfig.description,
            Precedence: groupConfig.precedence,
            RoleArn: groupConfig.roleArn,
            UserPoolId: userPoolId
        };

        // create the user pool group
        const group = await this.cognito.createGroup(params).promise();
        this.logger.silly("Created user pool group", group);
        return group;
    }

    /**
     * Get user pool details
     *
     * @param {String} userPoolId Id of existing user pool
     */
    async getUserPoolDetails(userPoolId) {
        const params = {
            UserPoolId: userPoolId
        };
        return await this.cognito.describeUserPool(params).promise();
    }

    async getToken(userPoolDomainUrl, clientId, clientSecret, code, redirectUri) {
        // jscs:disable requireCamelCaseOrUpperCaseIdentifiers
        const requestOptions = {
            method: 'POST',
            uri: `${userPoolDomainUrl}/oauth2/token`,
            auth: {
                user: clientId,
                pass: clientSecret
            },
            form: {
                grant_type: 'authorization_code',
                client_id: clientId,
                redirect_uri: redirectUri,
                code
            }
        };
        // jscs:enable requireCamelCaseOrUpperCaseIdentifiers

        const authResponse = await requestPromise(requestOptions);
        return JSON.parse(authResponse);
    }

    async updateToken(userPoolDomainUrl, clientId, clientSecret, refreshToken) {
        // jscs:disable requireCamelCaseOrUpperCaseIdentifiers
        const requestOptions = {
            method: 'POST',
            uri: `${userPoolDomainUrl}/oauth2/token`,
            auth: {
                user: clientId,
                pass: clientSecret
            },
            form: {
                grant_type: 'refresh_token',
                client_id: clientId,
                refresh_token: refreshToken
            }
        };
        // jscs:enable requireCamelCaseOrUpperCaseIdentifiers

        const authResponse = await requestPromise(requestOptions);
        return JSON.parse(authResponse);
    }
}

module.exports.CognitoUtil = CognitoUtil;
