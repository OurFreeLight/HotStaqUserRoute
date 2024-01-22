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
	 * The database connection.
	 */
	db: HotDBMySQL;

	constructor (api: HotAPI)
	{
		super (api, "admins");

		this.onPreRegister = async () =>
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
	 * The admin login. This checks to verify the user is an admin.
	 */
	protected async login (req: ServerRequest): Promise<any>
	{
		let user: User = await super.login (req);

		if (user.userType !== "admin")
			throw new Error (`Only admins are allowed to login to this route.`);

		return (user);
	}

	/**
	 * Edit a user.
	 * 
	 * **WARNING:** By default, this method can be used by anyone. To 
	 * prevent this, use "onServerPreExecute" to check the user's permissions.
	 */
	protected async editUser (req: ServerRequest): Promise<boolean>
	{
		const userObj: IUser = HotStaq.getParam ("user", req.jsonObj);
		const user: User = new User (userObj);

		await User.editUser (this.db, user);

		return (true);
	}

	/**
	 * Delete a user.
	 * 
	 * **WARNING:** By default, this method can be used by anyone. To 
	 * prevent this, use "onServerPreExecute" to check the user's permissions.
	 */
	protected async deleteUser (req: ServerRequest): Promise<boolean>
	{
		const userObj: IUser = HotStaq.getParam ("user", req.jsonObj);
		const user: User = new User (userObj);

		await User.deleteUser (this.db, user);

		return (true);
	}

	/**
	 * List users.
	 * 
	 * **WARNING:** By default, this method can be used by anyone. To 
	 * prevent this, use "onServerPreExecute" to check the user's permissions.
	 */
	protected async listUsers (req: ServerRequest): Promise<any>
	{
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