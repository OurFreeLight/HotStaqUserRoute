import { HotRoute, HotDBMySQL, HotServerType, 
	ConnectionStatus, HotStaq, 
	Hot, HotTestDriver, HotAPI, ServerRequest, DeveloperMode } from "hotstaq";

import { EmailConfig, IJWTToken, IUser, User } from "./User";

import * as ppath from "path";
import { HotRouteMethodParameter, PassType } from "hotstaq/build/src/HotRouteMethod";

/**
 * The User route.
 */
export class UserRoute extends HotRoute
{
	/**
	 * The email configs to use for each type of email to send.
	 * The available types are:
	 * * register
	 * * verify
	 * * forgotPassword
	 */
	emailConfigs: { [type: string]: EmailConfig };
	/**
	 * The database connection.
	 */
	db: HotDBMySQL;
	/**
	 * Executes when the route is registering. This is helpful for 
	 * creating tables, installing fixtures, etc. If not set, 
	 * this will call User.syncTables by default.
	 */
	onRegisteringRoute: ((db: HotDBMySQL) => Promise<void>);
	/**
	 * Executes before the route is registered with the web server.
	 */
	onUserPreRegisterRoute: () => Promise<void>;
	/**
	 * Test user data to use for executing tests.
	 */
	testUser: {
			email: string;
			password: string;
		};

	constructor (api: HotAPI, route: string = "users")
	{
		super (api.connection, route);

		this.emailConfigs = {};
		this.testUser = {
				email: "test3@freelight.org",
				password: "se45se45sdfrg3456"
			};

		this.onRegisteringRoute = async (db: HotDBMySQL) =>
			{
				let isDebug: boolean = false;

				if (this.connection.processor.mode === DeveloperMode.Development)
					isDebug = true;

				await User.syncTables (this.db, isDebug);
			};

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

					if (User.jwtSecretKey === "")
						throw new Error (`User.jwtSecretKey cannot be an empty string. Please set it to a valid secret key, or set the environemnt variable JWT_SECRET_KEY.`);

					if (this.onRegisteringRoute != null)
						await this.onRegisteringRoute (this.db);
				}

				return (true);
			};
		this.onUserPreRegisterRoute = async () =>
			{
				let userObjectDesc: HotRouteMethodParameter = {
					"type": "object",
					"description": "The user object.",
					// @ts-ignore
					"parameters": await HotStaq.convertInterfaceToRouteParameters (ppath.normalize (`${__dirname}/../../src/User.ts`), "IUser")
				};

				this.addMethod ({
					"name": "register",
					"onServerExecute": this.register,
					"description": `Registers a new user. If the user already exists, this will return an error. Additionally, if the new user is not verified manually, a verification code will be autogenerated and placed into the database.`,
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
							let tempUser: User = await User.getUser (this.db, this.testUser.email);
					
							if (tempUser != null)
								await User.deleteUser (this.db, tempUser);

							// @ts-ignore
							let resp = await api.users.register ({
									user: {
										"email": this.testUser.email,
										"password": this.testUser.password
									},
									verifyCodeOverride: "se45se57yse4"
								});

							driver.assert (resp.error == null, "User registration did not complete!");

							driver.persistentData.verifyCode = "se45se57yse4";

							driver.assert (driver.persistentData.verifyCode !== "", "User registration did not complete!");

							tempUser = await User.getUser (this.db, this.testUser.email);
							driver.assert (tempUser != null, "User registration did not complete!");
						}
					]
				});
			this.addMethod ({
					"name": "verifyUser",
					"onServerExecute": this.verifyUser,
					"description": "Verify a user's email address.",
					"parameters": {
						"email": {
								"type": "string",
								"required": true,
								"description": "The user's email."
							},
						"verificationCode": {
								"type": "string",
								"required": true,
								"description": "The user's verification code."
							}
					},
					"returns": "Returns true when the user has been verified successfully.",
					"testCases": [
						"verifyUserTest",
						async (driver: HotTestDriver): Promise<any> =>
						{
							// @ts-ignore
							let resp = await api.users.verifyUser ({
									"email": this.testUser.email,
									"verificationCode": driver.persistentData.verifyCode
								});

							driver.assert (resp.error == null, "User verification did not complete!");
							driver.assert (resp === true, "User verification did not complete!");
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
					"returns": userObjectDesc,
					"testCases": [
						"loginTest",
						async (driver: HotTestDriver): Promise<any> =>
						{
							// @ts-ignore
							let resp = await api.users.login ({
									user: {
										"email": this.testUser.email,
										"password": this.testUser.password
									}
								});

							driver.assert (resp.error == null, "User login did not complete!");
							driver.persistentData.jwtToken = resp.jwtToken;

							driver.assert (resp.password == null, "User object returning password!");
							driver.assert (resp.passwordSalt == null, "User object returning password!");
							driver.assert (resp.email !== "", "User login did not complete!");
							/// @todo Check the database and make sure the user is there.
						},
						"userLoginTest",
						async (driver: HotTestDriver): Promise<any> =>
						{
							let tempUser: User = await User.getUser (this.db, this.testUser.email);
					
							if (tempUser == null)
								throw new Error (`User ${this.testUser.email} not found!`);

							let logins: any[] = await User.getUserLogins (this.db, tempUser);

							driver.assert (logins.length === 0, "User login did not complete!");
						}
					]
				});
			this.addMethod ({
					"name": "logOut",
					"onServerExecute": this.logOut, 
					"parameters": {
						"user": {
							"type": "object",
							"required": true,
							"parameters": {
								"jwtToken": {
										"type": "string",
										"required": true,
										"description": "The user's JWT token to verify."
									}
								}
						}
					},
					"returns": "Returns true when the user has been logged out successfully.",
					"testCases": [
						"logOutTest",
						async (driver: HotTestDriver): Promise<any> =>
						{
							// @ts-ignore
							let resp = await api.users.logOut ({
									jwtToken: driver.persistentData.jwtToken
								});

							driver.assert (resp == true, "User not able to log out!");
						},
						"userLogOutTest",
						async (driver: HotTestDriver): Promise<any> =>
						{
							let decoded: IJWTToken = await User.decodeJWTToken (driver.persistentData.jwtToken);
							const userLoginId: string = decoded.userLoginId;

							/// @todo Verify that the user login was updated with the logout time.

							//driver.assert (resp == true, "User not able to log out!");
						}
					]
				});
			this.addMethod ({
					"name": "forgotPassword",
					"onServerExecute": this.forgotPassword, 
					"parameters": {
						"user": {
							"type": "object",
							"required": true,
							"parameters": {
								"email": {
										"type": "string",
										"required": true,
										"description": "The user's email to use to reset the password."
									}
								}
						}
					},
					"returns": "Returns true when the verification code has been sent.",
					"testCases": [
						"forgotPasswordTest",
						async (driver: HotTestDriver): Promise<any> =>
						{
							// @ts-ignore
							let resp = await api.users.forgotPassword ({
									email: this.testUser.email,
									verifyCodeOverride: "jasd78h4357"
								});

							driver.assert (resp.error == null, "User forgotten password did not complete!");
							driver.persistentData.verificationCode = "jasd78h4357";

							driver.assert (resp !== "", "User not able to start forgotten password process!");
						}
					]
				});
			this.addMethod ({
					"name": "verifyForgotPasswordCode",
					"onServerExecute": this.verifyForgotPasswordCode, 
					"description": "Verifies the forgotten password code received by the user and resets their password.",
					"parameters": {
						"user": {
							"type": "object",
							"required": true,
							"parameters": {
								"email": {
									"type": "string",
									"required": true,
									"description": "The user's email to reset."
								},
								"verificationCode": {
									"type": "string",
									"required": true,
									"description": "The user's verification code to authorize the password reset."
								},
								"newPassword": {
									"type": "string",
									"required": true,
									"description": "The new password to set."
								}
							}
						}
					},
					"returns": "Returns true when the user has been logged out successfully.",
					"testCases": [
						"verifyForgotPasswordCodeTest",
						async (driver: HotTestDriver): Promise<any> =>
						{
							// @ts-ignore
							let resp = await api.users.verifyForgotPasswordCode ({
									email: this.testUser.email,
									verificationCode: driver.persistentData.verificationCode,
									newPassword: "asw45as4we5se45se45"
								});

							driver.assert (resp.error == null, "User verify forgotten password did not complete!");
							driver.assert (resp === true, "User not able to start verify forgotten password process!");

							// @ts-ignore
							resp = await api.users.login ({
									user: {
										"email": this.testUser.email,
										"password": "asw45as4we5se45se45"
									}
								});

							driver.assert (resp.error == null, "User login did not complete!");
						}
					]
				});
			};
		this.onPreRegister = this.onUserPreRegisterRoute;
	}

	/**
	 * The user to register. By default, the user object that is returned 
	 * will not have password, passwordSalt, or verifyCode set. To access 
	 * the result of verifyCode, you can access it via onServerPostExecute 
	 * and access the req.passObject.jsonObj.verifyCode property.
	 * 
	 * The data passed in req.passObject.jsonObj will contain the following:
	 * { verifyCode: string;, user: User; }
	 */
	protected async register (req: ServerRequest): Promise<any>
	{
		const user: User = HotStaq.getParam ("user", req.jsonObj, true);

		HotStaq.getParam ("email", user, true);
		HotStaq.getParam ("password", user, true);

		let verifyCodeOverride: string = "";

		if (this.connection.processor.mode === Hot.DeveloperMode.Development)
			verifyCodeOverride = HotStaq.getParamDefault ("verifyCodeOverride", req.jsonObj, "");

		let newUser: User = new User (user);

		if (this.connection.processor.mode === Hot.DeveloperMode.Development)
			newUser.verified = true;

		const emailConfig: EmailConfig = this.emailConfigs["register"];

		await newUser.register (this.db, emailConfig, verifyCodeOverride);

		req.passObject.passType = PassType.Ignore;
		req.passObject.jsonObj = { verifyCode: newUser.verifyCode, user: newUser };

		newUser.verifyCode = "";

		return (newUser);
	}

	/**
	 * The user login.
	 * 
	 * The data passed in req.passObject.jsonObj will contain the following:
	 * { ip: string; verifyCode: string; user: User; }
	 */
	protected async login (req: ServerRequest): Promise<User>
	{
		const user: User = HotStaq.getParam ("user", req.jsonObj);

		const email: string = HotStaq.getParam ("email", user);
		const password: string = HotStaq.getParam ("password", user);
		const ip: string = (<string>req.req.headers["x-forwarded-for"]) || req.req.socket.remoteAddress;

		let userInfo: User = await User.login (this.db, ip, email, password, false);

		req.passObject.passType = PassType.Ignore;
		req.passObject.jsonObj = { ip: ip, verifyCode: userInfo.verifyCode, user: userInfo };

		return (userInfo);
	}

	/**
	 * Verify a user.
	 * 
	 * The data passed in req.passObject.jsonObj will contain the following:
	 * { email: string; }
	 */
	protected async verifyUser (req: ServerRequest): Promise<any>
	{
		const email: string = HotStaq.getParam ("email", req.jsonObj);
		const verificationCode: string = HotStaq.getParam ("verificationCode", req.jsonObj);

		await User.verifyUser (this.db, email, verificationCode);

		req.passObject.passType = PassType.Ignore;
		req.passObject.jsonObj = { email: email };

		return (true);
	}

	/**
	 * The user logout.
	 * 
	 * The data passed in req.passObject.jsonObj will contain the following:
	 * { jwtToken: string; }
	 */
	protected async logOut (req: ServerRequest): Promise<any>
	{
		const jwtToken: string = HotStaq.getParam ("jwtToken", req.jsonObj);

		await User.logOut (this.db, jwtToken);

		req.passObject.passType = PassType.Ignore;
		req.passObject.jsonObj = { jwtToken: jwtToken };

		return (true);
	}

	/**
	 * Starts the forgotten password process. When this is called, a 
	 * verification code (called verifyCode) is generated to be consumed by the backend. To access 
	 * the result of verifyCode, you can access it via onServerPostExecute 
	 * and access the req.passObject.jsonObj.verifyCode property.
	 * 
	 * The data passed in req.passObject.jsonObj will be an update containing the following:
	 * verificationCode: string;
	 */
	protected async forgotPassword (req: ServerRequest): Promise<boolean>
	{
		const email: string = HotStaq.getParam ("email", req.jsonObj);
		let verifyCodeOverride: string = "";

		if (this.connection.processor.mode === Hot.DeveloperMode.Development)
			verifyCodeOverride = HotStaq.getParamDefault ("verifyCodeOverride", req.jsonObj, "");

		const emailConfig: EmailConfig = this.emailConfigs["forgotPassword"];

		let verificationCode: string = await User.forgotPassword (this.db, email, emailConfig, verifyCodeOverride);

		req.passObject.passType = PassType.Update;
		req.passObject.jsonObj = verificationCode;

		return (true);
	}

	/**
	 * Verifies the forgotten password code and resets the user's password.
	 */
	protected async verifyForgotPasswordCode (req: ServerRequest): Promise<any>
	{
		const email: string = HotStaq.getParam ("email", req.jsonObj);
		const verificationCode: string = HotStaq.getParam ("verificationCode", req.jsonObj);
		const newPassword: string = HotStaq.getParam ("newPassword", req.jsonObj);

		await User.resetForgottenPassword (this.db, email, verificationCode, newPassword);

		return (true);
	}
}