import * as ppath from "path";

import { HotRoute, ServerRequest, HotTestDriver, HotStaq, HotServerType, 
	HotDBMySQL, ConnectionStatus, HotAPI, HotDBType, HttpError, 
	HotRouteMethodParameter, PassType, 
	HotRouteMethodParameterMap,
	HotValidation,
	ValidationOptions} from "hotstaq";
import { IJWTToken, IUser, User } from "./User";
import { UserRoute } from "./UserRoute";

import IUserObj from "./object-defs/IUser.json";

/**
 * Admin route.
 */
export class AdminRoute extends UserRoute
{
	/**
	 * Requires that each method requires authentication from a user of type.
	 * Set this to an empty string if you want to handle authentication yourself.
	 * Be warned, if you do this, you will need to check the user's permissions 
	 * on EVERY method within this route.
	 * 
	 * @default admin
	 */
	methodsRequireAuthType: string;
	/**
	 * The maximum limit for rows that can be returned.
	 */
	maxLimit: number = 1000;
	/**
	 * Executes before the route is registered with the web server.
	 */
	onAdminPreRegisterRoute: () => Promise<void>;
	/**
	 * The database connection.
	 */
	db: HotDBMySQL;
	/**
	 * If set to true, this will not validate the inputs. This should be set if 
	 * validations for every endpoint are already occurring outside of this module.
	 */
	alreadyValidatedInputs: boolean;

	constructor (api: HotAPI, routeName: string = "admins")
	{
		super (api, routeName);

		this.methodsRequireAuthType = "admin";
		this.maxLimit = 1000;
		this.alreadyValidatedInputs = false;

		this.onAdminPreRegisterRoute = async () =>
			{
				let userObjectDesc: HotRouteMethodParameter = {
						"type": "object",
						"description": "The user object.",
						"parameters": IUserObj as HotRouteMethodParameterMap
					};
		
				this.addMethod ({
						"name": "editUser",
						"tags": [routeName],
						"onServerExecute": this.editUser,
						"description": `Edit a user. The id set in the user object that is passed will be the id of the user that is edited.`,
						"parameters": {
							"user": userObjectDesc
						},
						"returns": "Returns true if the user was edited.",
						"testCases": [
							"editUserTest",
							async (driver: HotTestDriver): Promise<any> =>
							{
							}
						]
					});
				this.addMethod ({
						"name": "deleteUser",
						"tags": [routeName],
						"onServerExecute": this.deleteUser,
						"description": `Delete a user. The id set in the user object that is passed will be the id of the user that is deleted.`,
						"parameters": {
							"user": userObjectDesc
						},
						"returns": "Returns true if the user was deleted.",
						"testCases": [
							"deleteUserTest",
							async (driver: HotTestDriver): Promise<any> =>
							{
							}
						]
					});
				this.addMethod ({
						"name": "changePassword",
						"tags": [routeName],
						"onServerExecute": this.changePassword,
						"description": `Change a user's password. The id set in the user object that is passed will be the id of the user that has it's password changed.`,
						"parameters": {
							"user": userObjectDesc,
							"newPassword": {
								"type": "string",
								"description": "The new password to set."
							}
						},
						"returns": "Returns true if the user's password was changed.",
						"testCases": [
							"changePasswordTest",
							async (driver: HotTestDriver): Promise<any> =>
							{
							}
						]
					});
				this.addMethod ({
						"name": "getUser",
						"tags": [routeName],
						"onServerExecute": this.getUser,
						"description": `Get a user.`,
						"parameters": {
							"id": {
								"type": "string",
								"required": true,
								"description": "The id of the user to retrieve."
							}
						},
						"returns": userObjectDesc,
						"testCases": [
							"getUserTest",
							async (driver: HotTestDriver): Promise<any> =>
							{
								// @ts-ignore
								let resp = await api.admins.getUser ();
		
								driver.assert (resp.error == null, "Users was not returned.");
							}
						]
					});
				this.addMethod ({
						"name": "listUsers",
						"tags": [routeName],
						"onServerExecute": this.listUsers,
						"description": `Lists all users. This is meant to be performed by trusted admins or moderators.`,
						"parameters": {
							"search": {
								"type": "string",
								"required": false,
								"description": "Searches for a user by their first name, last name, or email."
							},
							"offset": {
								"type": "integer",
								"required": false
							},
							"limit": {
								"type": "integer",
								"required": false,
								"description": `The number of users to return. The maximum is ${this.maxLimit}`
							},
							"orderBy": {
								"type": "string",
								"required": false,
								"description": "The column to order by."
							}
						},
						"returns": {
								"type": "object",
								"description": "Returns the list of users.",
								"parameters": {
									"length": {
										"type": "integer",
										"description": "The number of users returned."
									},
									"data": {
										"type": "array",
										"description": "The list of users.",
										"items": userObjectDesc
									}
								}
							},
						"testCases": [
							"listUsersTest",
							async (driver: HotTestDriver): Promise<any> =>
							{
								// @ts-ignore
								let resp = await api.admins.listUsers ();
		
								driver.assert (resp.length > 0, "No users were returned.");
							}
						]
					});
					this.addMethod ({
							"name": "impersonate",
							"tags": [routeName],
							"onServerExecute": this.impersonate,
							"description": `Login as another user. Only admins can use this.`,
							"parameters": {
								"user": {
									"type": "object",
									"required": true,
									"parameters": {
										"email": {
												"type": "string",
												"required": true,
												"description": "The user's email."
											}
										}
									}
							},
							"returns": "The JWT token of the logged in user.",
							"testCases": [
								"impersonateTest",
								async (driver: HotTestDriver): Promise<any> =>
								{
								}
							]
						});
			};
		this.onPreRegister = async () =>
			{
				await this.onUserPreRegisterRoute ();
				await this.onAdminPreRegisterRoute ();
			};
	}

	/**
	 * A wrapper function for getParam
	 */
	protected getParam (validate: string | HotValidation, name: string, objWithParam: any, 
		request: ServerRequest, required?: boolean, throwException?: boolean, strict?: boolean): Promise<any>
	{
		if (this.alreadyValidatedInputs === true)
			return (objWithParam[name]);

		return (HotStaq.getParam (validate, name, objWithParam, request, required, throwException, new ValidationOptions (strict)));
	}

	/**
	 * A wrapper function for getParamDefault
	 */
	protected getParamDefault (validate: string | HotValidation, name: string, objWithParam: any, 
		defaultValue: any, request: ServerRequest, strict?: boolean): Promise<any>
	{
		if (this.alreadyValidatedInputs === true)
			return (objWithParam[name]);

		return (HotStaq.getParamDefault (validate, name, objWithParam, defaultValue, request, new ValidationOptions (strict)));
	}

	/**
	 * The admin to register. By default this prevents admins from being able 
	 * to register. To enable this, override this method, and call super.register.
	 */
	protected async register (req: ServerRequest): Promise<any>
	{
		throw new Error ("Unable to register admins using this route.");
	}

	/**
	 * Check a user's authentication.
	 */
	protected async checkAuth (req: ServerRequest): Promise<void>
	{
		if (this.methodsRequireAuthType !== "")
		{
			const jwtToken: string = HotStaq.getParamUnsafe ("jwtToken", req.jsonObj);
			const decoded: IJWTToken = await User.decodeJWTToken (jwtToken);
			const authUser: IUser = decoded.user;

			if (authUser.userType !== this.methodsRequireAuthType)
				throw new HttpError (`Only user of type ${this.methodsRequireAuthType} is allowed to use this method.`, 401);
		}
	}

	/**
	 * The admin login. This checks to verify the user is of the user type set in 
	 * this.methodsRequireAuthType.
	 */
	protected async login (req: ServerRequest): Promise<any>
	{
		let user: User = await super.login (req);

		await this.checkAuth (req);

		return (user);
	}

	/**
	 * Edit a user.
	 */
	protected async editUser (req: ServerRequest): Promise<boolean>
	{
		await this.checkAuth (req);

		const userObj: IUser = await this.getParam ("IUser", "user", req.jsonObj, req);
		const user: User = new User (userObj);

		await User.editUser (this.db, user);

		return (true);
	}

	/**
	 * Delete a user.
	 */
	protected async deleteUser (req: ServerRequest): Promise<boolean>
	{
		await this.checkAuth (req);

		const userObj: IUser = await this.getParam ("IUser", "user", req.jsonObj, req);
		const user: User = new User (userObj);

		await User.deleteUser (this.db, user);

		return (true);
	}

	/**
	 * Change a user's password.
	 */
	protected async changePassword (req: ServerRequest): Promise<any>
	{
		await this.checkAuth (req);

		const userObj: IUser = await this.getParam ("IUser", "user", req.jsonObj, req);
		const user: User = new User (userObj);
		const newPassword: string = await this.getParam ("IUser", "newPassword", req.jsonObj, req);

		await User.changePassword (this.db, user, newPassword);

		return (true);
	}

	/**
	 * Get a user.
	 */
	protected async getUser (req: ServerRequest): Promise<any>
	{
		await this.checkAuth (req);

		const id: string = await this.getParam ("IUser", "id", req.jsonObj, req);

		let user = await User.getUserById (this.db, id, false);

		return (user);
	}

	/**
	 * List users. This is meant to be performed by trusted admins or moderators.
	 * 
	 * This performs a select on the users table.
	 */
	protected async listUsers (req: ServerRequest): Promise<{ length: number; data: any[]; }>
	{
		await this.checkAuth (req);

		const search: string = await this.getParamDefault ("IUser", "search", req.jsonObj, null, req);
		const offset: number = await this.getParamDefault ("IUser", "offset", req.jsonObj, 0, req);
		const limit: number = await this.getParamDefault ("IUser", "limit", req.jsonObj, 20, req);
		let orderBy: string = await this.getParamDefault ("IUser", "orderBy", req.jsonObj, "display_name", req);
		
		if (limit > this.maxLimit)
			throw new Error (`Limit cannot exceed ${this.maxLimit}`);

		orderBy = `u.${orderBy}`;

		let query: string = `SELECT u.*, COUNT(*) OVER() AS total_count FROM users u ORDER BY ? LIMIT ?, ?;`;

		if (this.db.type === HotDBType.Postgres)
			query = `SELECT u.*, COUNT(*) OVER() AS total_count FROM users u ORDER BY $1 OFFSET $2 LIMIT $3;`;

		let args: any[] = [orderBy, offset, limit];

		if (search != null)
		{
			query = `SELECT 
				u.*,
				COUNT(*) OVER() AS total_count
				FROM users u
				WHERE first_name LIKE ? OR last_name LIKE ? OR email LIKE ? OR display_name LIKE $3
				ORDER BY ? 
				LIMIT ?, ?;`;

			if (this.db.type === HotDBType.Postgres)
			{
				//query = `SELECT * FROM users WHERE first_name LIKE $1 OR last_name LIKE $2 OR email LIKE $3 OFFSET $4 LIMIT $5;`;
				query = `SELECT 
					u.*, 
					COUNT(*) OVER() AS total_count
					FROM users u
					WHERE first_name ILIKE $1 OR last_name ILIKE $2 OR email ILIKE $3 OR display_name ILIKE $3
					ORDER BY $4 
					OFFSET $5 LIMIT $6;`;
			}

			args = [`%${search}%`, `%${search}%`, `%${search}%`, orderBy, offset, limit];
		}

		let results = await this.db.query (query, args);

		if (results.error != null)
			throw new HttpError (`Unable to list users: ${results.error}`);

		let users: IUser[] = [];
		let length: number = 0;

		if (results.results.length > 0)
			length = results.results[0].total_count;

		for (let i = 0; i < results.results.length; i++)
		{
			let row = results.results[i];

			users.push (User.getUserFromResult (row));
		}

		return ({ length: length, data: users });
	}

	/**
	 * Login as another user. Only admins can use this.
	 */
	protected async impersonate (req: ServerRequest): Promise<any>
	{
		await this.checkAuth (req);

		const user: User = await this.getParam ("IUser", "user", req.jsonObj, req);
		const email: string = await this.getParam ("IUser", "email", user, req);
		const ip: string = (<string>req.req.headers["x-forwarded-for"]) || req.req.socket.remoteAddress;

		let userInfo: User = await User.login (this.db, ip, email, "", false, true);

		req.passObject.passType = PassType.Ignore;
		req.passObject.jsonObj = { ip: ip, verifyCode: userInfo.verifyCode, user: userInfo };

		return (userInfo);
	}
}