const AWS = require('aws-sdk');
const crypto = require('crypto');

class UserUtil {
    constructor(serviceLocator) {
        this.commons = serviceLocator.get('commons');
        this.config = serviceLocator.get('config');
        this.logger = serviceLocator.get('logger');
        this.cognito = new AWS.CognitoIdentityServiceProvider({
            apiVersion: '2016-04-18'
        });
    }

    /**
     * Create a Cognito user with custom attributes
     * @param {Object} user User with attribute values
     * @param {String} user.tenantId Tenant ID of the new user.
     * @param {String} user.userId Username of the new user.
     * @param {String} user.password Temporary password of the new user.
     * @param {String} user.firstName First name of the new user.
     * @param {String} user.lastName Last name of the new user.
     * @param {String} user.email Email of the new user.
     * @param {String} user.phoneNumber Phone number of the new user.
     * @param {String} user.userPoolId Id of the existing user pool.
     */
    async createUser(user) {
        // create params for user creation
        const params = {
            UserPoolId: user.userPoolId, /* required */
            Username: user.userId, /* required */
            TemporaryPassword: user.password,
            DesiredDeliveryMediums: [
                'EMAIL'
            ],
            ForceAliasCreation: true,
            UserAttributes: [{
                Name: 'email',
                Value: user.email
            },
            {
                Name: 'email_verified',
                Value: 'True'
            },
            {
                Name: 'custom:tenantId',
                Value: user.tenantId
            }]
        };
        if (user.phoneNumber) {
            params.UserAttributes.push({
                Name: 'phone_number',
                Value: user.phoneNumber
            });
        }
        if (user.firstName) {
            params.UserAttributes.push({
                Name: 'given_name',
                Value: user.firstName
            });
        }
        if (user.lastName) {
            params.UserAttributes.push({
                Name: 'family_name',
                Value: user.lastName
            });
        }

        const cognitoUser = await this.cognito.adminCreateUser(params).promise();
        this.logger.debug('Created cognito user', cognitoUser);
        return cognitoUser;
    }

    /**
     * Update a Cognito user attributes
     * @param {Object} user User with attribute values
     * @param {String} user.userId Username of the user.
     * @param {String} user.firstName First name of the user.
     * @param {String} user.lastName Last name of the user.
     * @param {String} user.email Email of the user.
     * @param {String} user.phoneNumber Phone number of the user.
     * @param {String} user.userPoolId Id of the existing user pool.
     */
    async updateUser(user) {
        const params = {
            UserPoolId: user.userPoolId, /* required */
            Username: user.userId, /* required */
            UserAttributes: []
        };

        if (user.email) {
            params.UserAttributes.push(
                {
                    Name: 'email',
                    Value: user.email
                }
            );
        }
        if (user.email) {
            params.UserAttributes.push(
                {
                    Name: 'email',
                    Value: user.email
                }
            );
        }
        if (user.firstName) {
            params.UserAttributes.push(
                {
                    Name: 'given_name',
                    Value: user.firstName
                }
            );
        }
        if (user.lastName) {
            params.UserAttributes.push(
                {
                    Name: 'family_name',
                    Value: user.lastName
                }
            );
        }
        if (user.tenantId) {
            params.UserAttributes.push(
                {
                    Name: 'custom:tenantId',
                    Value: user.tenantId
                }
            );
        }
        const cognitoUser = await this.cognito.adminUpdateUserAttributes(params).promise();
        this.logger.debug('Updated cognito user', cognitoUser);
        return cognitoUser;
    }

    /**
     * Delete a user from pool
     *
     * @param {String} userPoolId Id of the existing user pool
     * @param {String} userId Username of the user
     */
    async deleteUser(userPoolId, userId) {
        // delete params for user deletion
        const params = {
            UserPoolId: userPoolId,
            Username: userId
        };
        const cognitoUser = await this.cognito.adminDeleteUser(params).promise();
        this.logger.debug('Deleted cognito user', cognitoUser);
        return cognitoUser;
    }

    /**
     * Login user
     *
     * @param {Object} userData User information required to login
     * @param {String} userData.userId Username of the user.
     * @param {String} userData.password Password of the user.
     * @param {String} userPoolId Id of the existing user pool
     * @param {String} clientId Id of the existing user pool client
     * @param {String} clientSecret Secret of the existing user pool client
     */
    async loginUser(userData, userPoolId, clientId, clientSecret) {
        if (!userData.userId) {
            throw new this.commons.exceptions.PreconditionFailed('Field "userId" not provided');
        }
        if (!userData.password) {
            throw new this.commons.exceptions.PreconditionFailed('Field "password" not provided');
        }
        // AWS SECRET_HASH should be Base64(HMAC_SHA256("Client Secret Key", "Username" + "Client Id"))
        const secretHash = crypto.createHmac('SHA256', clientSecret).update(userData.userId + clientId).digest('base64');
        const userId = userData.userId;
        const password = userData.password;
        const authParams = {
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: clientId,
            // UserPoolId: userPoolId,
            AuthParameters: {
                USERNAME: userId,
                PASSWORD: password,
                SECRET_HASH: secretHash
            }
        };

        const sessionData = await this.cognito.initiateAuth(authParams).promise();
        this.logger.debug('sessionData', sessionData);
        return sessionData;
    }

    /**
     * Authenticate user and update new password
     *
     * @param {Object} userData User information required to login
     * @param {String} userData.userId Username of the user.
     * @param {String} userData.newPassword Password of the user to update.
     * @param {String} session Sessoin of the auth challenge for new password
     * @param {String} clientId Id of the existing user pool client
     * @param {String} clientSecret Secret of the existing user pool client
     */
    async respondToAuthChallengeNewPassword(userData, session, clientId, clientSecret) {
        if (!userData.userId) {
            throw new this.commons.exceptions.PreconditionFailed('Field "userId" not provided');
        }
        if (!userData.newPassword) {
            throw new this.commons.exceptions.PreconditionFailed('Field "newPassword" not provided');
        }
        const secretHash = crypto.createHmac('SHA256', clientSecret).update(userData.userId + clientId).digest('base64');
        const params = {
            ChallengeName: 'NEW_PASSWORD_REQUIRED',
            ClientId: clientId,
            ChallengeResponses: {
                USERNAME: userData.userId,
                NEW_PASSWORD: userData.newPassword,
                SECRET_HASH: secretHash
            },
            Session: session
        };
        return await this.cognito.respondToAuthChallenge(params).promise();
    }

    /**
     * Add user to group
     *
     * @param {String} groupName Group name of existing group.
     * @param {String} userId Username of existing user.
     * @param {String} userPoolId Id of existing user pool
     */
    async addUserToGroup(groupName, userId, userPoolId) {
        const params = {
            GroupName: groupName,
            Username: userId,
            UserPoolId: userPoolId
        };
        return await this.cognito.adminAddUserToGroup(params).promise();
    }

    /**
     * Remove user from group
     *
     * @param {String} groupName Group name of existing group.
     * @param {String} userId Username of existing user.
     * @param {String} userPoolId Id of existing user pool
     */
    async removeUserFromGroup(groupName, userId, userPoolId) {
        const params = {
            GroupName: groupName,
            Username: userId,
            UserPoolId: userPoolId
        };
        return await this.cognito.adminRemoveUserFromGroup(params).promise();
    }

    /**
     * Get user details
     *
     * @param {String} userId Username of existing user.
     * @param {String} userPoolId Id of existing user pool
     */
    async getUser(userId, userPoolId) {
        const params = {
            Username: userId,
            UserPoolId: userPoolId
        };
        return await this.cognito.adminGetUser(params).promise();
    }
}

module.exports.CognitoUtil = CognitoUtil;
