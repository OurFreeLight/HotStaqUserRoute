import * as ppath from "path";

import { HotRoute, ServerRequest, HotTestDriver, HotStaq, HotServerType, HotDBMySQL, ConnectionStatus, HotAPI } from "hotstaq";
import { IJWTToken, IUser, User } from "./User";
import { UserRoute } from "./UserRoute";
import { HotRouteMethodParameter, PassType } from "hotstaq/build/src/HotRouteMethod";

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
	 * Executes before the route is registered with the web server.
	 */
	onAdminPreRegisterRoute: () => Promise<void>;
	/**
	 * The database connection.
	 */
	db: HotDBMySQL;

	constructor (api: HotAPI, routeName: string = "admins")
	{
		super (api, routeName);

		this.methodsRequireAuthType = "admin";

		this.onAdminPreRegisterRoute = async () =>
			{
				let userObjectDesc: HotRouteMethodParameter = {
						"type": "object",
						"description": "The user object.",
						// @ts-ignore
						"parameters": await HotStaq.convertInterfaceToRouteParameters (ppath.normalize (`${__dirname}/../../src/User.ts`), "IUser")
					};
		
				this.addMethod ({
						"name": "editUser",
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
						"name": "listUsers",
						"onServerExecute": this.listUsers,
						"description": `Lists all users.`,
						"parameters": {
							"offset": {
								"type": "int",
								"required": false
							},
							"limit": {
								"type": "int",
								"required": false
							}
						},
						"returns": "Returns the list of users.",
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
			};
		this.onPreRegister = async () =>
			{
				await this.onUserPreRegisterRoute ();
				await this.onAdminPreRegisterRoute ();
			};
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
			const jwtToken: string = HotStaq.getParam ("jwtToken", req.jsonObj);
			const decoded: IJWTToken = await User.decodeJWTToken (jwtToken);
			const authUser: IUser = decoded.user;

			if (authUser.userType !== this.methodsRequireAuthType)
				throw new Error (`Only user of type ${this.methodsRequireAuthType} is allowed to use this method.`);
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

		const userObj: IUser = HotStaq.getParam ("user", req.jsonObj);
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

		const userObj: IUser = HotStaq.getParam ("user", req.jsonObj);
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

		const userObj: IUser = HotStaq.getParam ("user", req.jsonObj);
		const user: User = new User (userObj);
		const newPassword: string = HotStaq.getParam ("newPassword", req.jsonObj);

		await User.changePassword (this.db, user, newPassword);

		return (true);
	}

	/**
	 * List users.
	 */
	protected async listUsers (req: ServerRequest): Promise<any>
	{
		await this.checkAuth (req);

		const search: string = HotStaq.getParamDefault ("search", req.jsonObj, null);
		const offset: number = HotStaq.getParamDefault ("offset", req.jsonObj, 0);
		const limit: number = HotStaq.getParamDefault ("limit", req.jsonObj, 20);

		let query: string = `SELECT * FROM users LIMIT ?, ?;`;
		let args: any[] = [offset, limit];

		if (search != null)
		{
			query = `SELECT * FROM users WHERE firstName LIKE ? OR lastName LIKE ? OR email LIKE ? LIMIT ?, ?;`;
			args = [`%${search}%`, `%${search}%`, `%${search}%`, offset, limit];
		}

		let results = await this.db.query (query, args);

		if (results.error != null)
			throw new Error (`Unable to list users: ${results.error}`);

		let users: IUser[] = [];

		for (let i = 0; i < results.results.length; i++)
		{
			let row = results.results[i];

			users.push (User.getUserFromResult (row));
		}

		return (users);
	}
}