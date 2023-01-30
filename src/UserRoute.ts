import { HotRoute, HotDBMySQL, HotServerType, 
	ConnectionStatus, HotStaq, 
	Hot, HotTestDriver, HotAPI, ServerRequest } from "hotstaq";

import { User } from "./User";

/**
 * The User route.
 */
export class UserRoute extends HotRoute
{
	/**
	 * The database connection.
	 */
	db: HotDBMySQL;

	constructor (api: HotAPI)
	{
		super (api.connection, "users");

		if (HotStaq.isWeb === false)
		{
			this.onRegister = async () =>
				{
					if (api.connection.type !== HotServerType.Generate)
					{
						if (process.env["DATABASE_DISABLE"] != null)
						{
							if (process.env["DATABASE_DISABLE"] === "1")
								return (true);
						}

						this.db = (<HotDBMySQL>this.connection.api.db);

						if (this.db.connectionStatus !== ConnectionStatus.Connected)
							return (true);

						let debug: boolean = false;

						if (process.env["DEBUG"] != null)
						{
							if (process.env["DEBUG"] === "1")
								debug = true;
						}

						await User.syncTables (this.db, debug);
					}

					return (true);
				};
		}

		this.addMethod ({
				"name": "register",
				"onServerExecute": this.register,
				"parameters": {
					"user": {
						"type": "object",
						"required": true,
						"parameters": {
							"email": {
									"type": "string",
									"required": true,
									"description": "The user's email."
								},
							"password": {
									"type": "string",
									"required": true,
									"description": "The user's password."
								}
							}
					}
				},
				"returns": "Returns true when the user has been registered successfully.",
				"testCases": [
					"registerTest",
					async (driver: HotTestDriver): Promise<any> =>
					{
						// @ts-ignore
						let resp = await api.users.register ({
								token: "test",
								user: {
									"email": "test3@freelight.org",
									"password": "se45se45sdfrg3456"
								}
							});

						if (resp.error != null)
						{
							if (resp.error === "Email has already been used.")
							{
								driver.assert (true, "User registration did not complete!");

								return;
							}
						}

						driver.assert (resp === true, "User registration did not complete!");
						/// @todo Check the database and make sure the user is there.
					}
				]
			});
		this.addMethod ({
				"name": "login",
				"onServerExecute": this.login, 
				"parameters": {
					"user": {
						"type": "object",
						"required": true,
						"parameters": {
							"email": {
									"type": "string",
									"required": true,
									"description": "The user's email."
								},
							"password": {
									"type": "string",
									"required": true,
									"description": "The user's password."
								}
							}
					}
				},
				"returns": {
					"type": "object",
					"parameters": {
						"enabled": {
								"type": "boolean",
								"description": "Is the user enabled?"
							},
						"firstName": {
								"type": "string",
								"description": "The user's first name."
							},
						"lastName": {
								"type": "string",
								"description": "The user's last name."
							},
						"email": {
								"type": "string",
								"description": "The user's email."
							},
						"password": {
								"type": "string",
								"description": "This will return as an empty string."
							}
					}
				},
				"testCases": [
					"loginTest",
					async (driver: HotTestDriver): Promise<any> =>
					{
						// @ts-ignore
						let resp = await api.users.login ({
								user: {
									"email": "test3@freelight.org",
									"password": "se45se45sdfrg3456"
								}
							});

						driver.assert (resp.password == null, "User object returning password!");
						driver.assert (resp.passwordSalt == null, "User object returning password!");
						driver.assert (resp.email !== "", "User login did not complete!");
						/// @todo Check the database and make sure the user is there.
					}
				]
			});
	}

	/**
	 * The user to register.
	 */
	protected async register (req: ServerRequest): Promise<any>
	{
		const token: string = HotStaq.getParam ("token", req.jsonObj, true);
		const user: User = HotStaq.getParam ("user", req.jsonObj, true);

		HotStaq.getParam ("email", user, true);
		HotStaq.getParam ("password", user, true);

		let newUser: User = new User (user);

		if (this.connection.processor.mode !== Hot.DeveloperMode.Development)
			newUser.verified = true;

		await newUser.register (this.db);

		return (true);
	}

	/**
	 * The user login.
	 */
	protected async login (req: ServerRequest): Promise<any>
	{
		const user: User = HotStaq.getParam ("user", req.jsonObj);

		const email: string = HotStaq.getParam ("email", user);
		const password: string = HotStaq.getParam ("password", user);
		const ip: string = (<string>req.req.headers["x-forwarded-for"]) || req.req.socket.remoteAddress;

		let userInfo: User = await User.login (this.db, ip, email, password);

		if (userInfo.enabled === false)
			throw new Error (`This account has been disabled.`);

		if (userInfo.verified === false)
			throw new Error (`This account has not been verified yet.`);

		return (userInfo);
	}
}