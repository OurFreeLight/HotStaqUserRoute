import { HotRoute, ServerRequest, HotTestDriver, HotStaq, HotServerType, HotDBMySQL, ConnectionStatus, HotAPI } from "hotstaq";
import { IJWTToken, IUser, User } from "./User";
import { UserRoute } from "./UserRoute";
import { PassType } from "hotstaq/build/src/HotRouteMethod";

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
	 * List users.
	 * 
	 * **WARNING:** By default, this method can be used by anyone. To 
	 * prevent this, use "onServerPreExecute" to check the user's permissions. 
	 * For better performance, be sure to use User.decodeJWTToken in onServerPreExecute
	 * to decode the JWT token and store the user in req.passObject.jsonObj. Without 
	 * this, the user will be decoded twice.
	 */
	protected async listUsers (req: ServerRequest): Promise<any>
	{
		let user: IUser = null;

		if (req.passObject.passType === PassType.Update)
			user = req.passObject.jsonObj;
		else
		{
			const jwtToken: string = HotStaq.getParam ("jwtToken", req.jsonObj);
			let decoded: IJWTToken = await User.decodeJWTToken (jwtToken);
			user = decoded.user;
		}

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

			users.push (row);
		}

		return (users);
	}
}