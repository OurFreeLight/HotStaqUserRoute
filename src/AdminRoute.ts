import { HotRoute, ServerRequest, HotTestDriver, HotStaq, HotServerType, HotDBMySQL, ConnectionStatus, HotAPI } from "hotstaq";
import { IJWTToken, IUser, User } from "./User";
import { UserRoute } from "./UserRoute";

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
	 * The user to register.
	 */
	protected async register (req: ServerRequest): Promise<any>
	{
		throw new Error ("Unable to register admins using this route.");
	}

	/**
	 * The user login.
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
	 */
	protected async listUsers (req: ServerRequest): Promise<any>
	{
		const jwtToken: string = HotStaq.getParam ("jwtToken", req.jsonObj);
		let decoded: IJWTToken = await User.decodeJWTToken (jwtToken);
		const user: IUser = decoded.user;

		const search: string = HotStaq.getParamDefault ("search", req.jsonObj, null);
		const offset: number = HotStaq.getParamDefault ("offset", req.jsonObj, 0);
		const limit: number = HotStaq.getParamDefault ("limit", req.jsonObj, 20);

		if (user.userType !== "admin")
			throw new Error (`Only admins are allowed to login to this route.`);

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