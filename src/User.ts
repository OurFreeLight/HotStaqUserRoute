import { HotDBMySQL, MySQLResults } from "hotstaq";
import * as crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import { SESClient, SESClientConfig, SendEmailCommand } from "@aws-sdk/client-ses";

/**
 * The user.
 */
export interface IUser
{
	/**
	 * Is the user enabled?
	 */
	enabled?: boolean;
	/**
	 * The id.
	 */
	id?: string;
	/**
	 * The user type.
	 */
	userType?: string;
	/**
	 * The user's first name.
	 */
	firstName?: string;
	/**
	 * The user's last name.
	 */
	lastName?: string;
	/**
	 * The email.
	 */
	email?: string;
	/**
	 * The password.
	 */
	password?: string;
	/**
	 * The password salt.
	 */
	passwordSalt?: string;
	/**
	 * The verification code.
	 */
	verifyCode?: string;
	/**
	 * The registered date.
	 */
	registeredDate?: Date;
	/**
	 * The login date.
	 */
	loginDate?: Date;
	/**
	 * Indicates if the account has been verified.
	 */
	verified?: boolean;
	/**
	 * The player's ip.
	 */
	ip?: string;
	/**
	 * The player's JWT token.
	 */
	jwtToken?: string;
}

/**
 * The email config.
 */
export interface EmailConfig
{
	/**
	 * The AWS SES client configuration.
	 */
	sesClientConfig: SESClientConfig;
	/**
	 * The subject of the email.
	 */
	subject: string;
	/**
	 * The from address. Where the email is being sent from.
	 */
	fromAddress: string;
	/**
	 * The body of the email to send.
	 */
	body: (user: IUser, verificationCode: string) => string;
}

/**
 * The user's JWT token.
 */
export interface IJWTToken
{
	/**
	 * The user information.
	 */
	user: IUser;
	/**
	 * The user's IP that was used to login.
	 */
	ip: string;
	/**
	 * The user's login id in the database.
	 */
	userLoginId: string;
}

/**
 * The user.
 */
export class User implements IUser
{
	/**
	 * Is the user enabled?
	 */
	enabled: boolean;
	/**
	 * The id.
	 */
	id: string;
	/**
	 * The user type.
	 */
	userType: string;
	/**
	 * The user's first name.
	 */
	firstName: string;
	/**
	 * The user's last name.
	 */
	lastName: string;
	/**
	 * The email.
	 */
	email: string;
	/**
	 * The password.
	 */
	password: string;
	/**
	 * The password salt.
	 */
	passwordSalt: string;
	/**
	 * The verification code.
	 */
	verifyCode: string;
	/**
	 * The registered date.
	 */
	registeredDate: Date;
	/**
	 * The login date.
	 */
	loginDate: Date;
	/**
	 * Indicates if the account has been verified.
	 */
	verified: boolean;
	/**
	 * The player's ip.
	 */
	ip: string;
	/**
	 * The player's JWT token.
	 */
	jwtToken: string;
	/**
	 * The secret key used for the JWT generation.
	 */
	static jwtSecretKey: string = process.env["JWT_SECRET_KEY"] || "";
	/**
	 * The event to fire when a user is registered into the database.
	 * This must return a user, WITH A USER ID SET.
	 */
	static onRegisterInsert: (user: User, passwordHash: string, passwordSalt: string, verificationCode: string, 
		verified: number) => Promise<User> = null;
	/**
	 * The event to fire when a user has successfully logged in, and their 
	 * password has been rehashed, and being updated in the database.
	 */
	static onLoginRegenPasswordUpdate: (user: User, passwordHash: string, passwordSalt: string) => Promise<void> = null;
	/**
	 * The event to fire when a user has successfully logged in, and their 
	 * login info is being inserted into the database. The user login id 
	 * of the new record is returned to be added to the issued JWT token.
	 */
	static onLoginInsertUserLogin: (user: User, ip: string) => Promise<string> = null;
	/**
	 * The event to fire when a user has successfully logged out, and their 
	 * JWT token invalidated. This updates the user login record in the database
	 * to indicate when the user has logged out.
	 */
	static onLogoutUpdateUserLogin: (user: IUser, userLoginId: string) => Promise<void> = null;
	/**
	 * The event to fire when a user is being verified. This updates the user's 
	 * record in the database to indicate that the user has been verified.
	 */
	static onVerifyUserUpdate: (user: User) => Promise<void> = null;
	/**
	 * The event to fire when a user's forgotten password has started. This updates 
	 * the user's verifyCode in the database so the user can update their password.
	 */
	static onForgotPasswordUpdate: (user: User) => Promise<void> = null;
	/**
	 * The event to fire when a user's forgotten password has been reset. This updates 
	 * the user's new password has and salt in the database.
	 */
	static onResetForgottenPasswordUpdate: (user: User, 
		passwordHash: string, passwordSalt: string) => Promise<void> = null;
	/**
	 * The event to fire when a user is being retrieved from the database by their email.
	 * This needs to return the raw user data from the database. If this returns null, 
	 * this indicates the user was not found.
	 */
	static onGetUserSelect: (email: string) => Promise<any> = null;
	/**
	 * The list of invalid JWT tokens. If the token is set to true, it is invalid.
	 */
	static invalidJWTTokens: { [jwtToken: string]: boolean } = {};

	constructor (user: IUser = {})
	{
		this.enabled = user.enabled || true;
		this.id = user.id || "";
		this.userType = user.userType || "user";
		this.firstName = user.firstName || "";
		this.lastName = user.lastName || "";
		this.email = user.email || "";
		this.password = user.password || "";
		this.passwordSalt = user.passwordSalt || "";
		this.verifyCode = user.verifyCode || "";
		this.registeredDate = user.registeredDate || null;
		this.loginDate = user.loginDate || null
		this.verified = user.verified || false;
		this.ip = user.ip || "";
		this.jwtToken = user.jwtToken || "";
	}

	/**
	 * Sync the table.
	 */
	static async syncTables (db: HotDBMySQL, debug: boolean): Promise<void>
	{
		if (db == null)
			throw new Error ("UserRoute: Database is not connected");

		await db.query (
			`create table if not exists users (
					id             BINARY(16)     NOT NULL,
					userType       VARCHAR(256)   DEFAULT 'user',
					firstName      VARCHAR(256)   DEFAULT '',
					lastName       VARCHAR(256)   DEFAULT '',
					email          VARCHAR(256)   DEFAULT '',
					password       VARCHAR(256)   DEFAULT '',
					passwordSalt   VARCHAR(256)   DEFAULT '',
					verifyCode     VARCHAR(256)   DEFAULT '',
					verified       TINYINT(1)     DEFAULT '0',
					registeredDate DATETIME       DEFAULT NOW(),
					enabled        TINYINT(1)     DEFAULT '1',
					PRIMARY KEY (id)
				)`);
		await db.query (
			`create table if not exists userLogins (
					id             BINARY(16)     NOT NULL,
					userId         BINARY(16)     DEFAULT '',
					ip             VARCHAR(256)   DEFAULT '',
					loginDate      DATETIME       DEFAULT NOW(),
					logOutDate     DATETIME       DEFAULT NULL,
					PRIMARY KEY (id)
				)`);

		if (debug == true)
		{
			let results: MySQLResults = await db.queryOne (`select COUNT(*) from users;`);

			if (results.results["COUNT(*)"] < 1)
			{
				let testPlayers = [
						new User ({
							firstName: "John",
							lastName: "Doe",
							email: "test1@freelight.org",
							password: "a867h398jdg",
							verified: true
						}),
						new User ({
							firstName: "Jane",
							lastName: "Smith",
							email: "test2@freelight.org",
							password: "ai97w3a98w3498",
							verified: true }),
						new User ({
							userType: "admin",
							firstName: "Bob",
							lastName: "Derp",
							email: "admin1@freelight.org",
							password: "a98j3w987aw3h47u",
							verified: true })
					];

				for (let iIdx = 0; iIdx < testPlayers.length; iIdx++)
				{
					let testPlayer = testPlayers[iIdx];

					await testPlayer.register (db);
				}
			}
		}
	}

	/**
	 * Generate salt for a hash.
	 */
	protected static async generateSalt (): Promise<string>
	{
		const rounds: number = 10;
		const salt: string = await bcrypt.genSalt (rounds);

		return (salt);
	}

	/**
	 * Generate a hash.
	 */
	protected static async generateHash (text: string, salt: string): Promise<string>
	{
		const hash: string = await bcrypt.hash (text, salt);

		return (hash);
	}

	/**
	 * Convert a binary UUID to a string UUID.
	 */
	static fromBinaryToUUID (buffer: Buffer): string
	{
		const hex: string = buffer.toString ('hex');
		return `${hex.substr (0, 8)}-${hex.substr (8, 4)}-${hex.substr (12, 4)}-${hex.substr (16, 4)}-${hex.substr (20)}`;
	}

	/**
	 * Register a user.
	 */
	async register (db: HotDBMySQL): Promise<User>
	{
		let tempUser: User | null = await User.getUser (db, this.email);

		if (tempUser != null)
			throw new Error (`Email has already been used.`);

		const salt: string = await User.generateSalt ();
		const hash: string = await User.generateHash (this.password, salt);

		// For security purposes, clear the password.
		this.password = "";

		let verified: number = 0;
		let verificationCode: string = "";

		if (this.verified === true)
			verified = 1;

		if (process.env["AUTO_VERIFY_USERS"] != null)
		{
			if (process.env["AUTO_VERIFY_USERS"] === "1")
				verified = 1;
		}

		if (verified === 0)
			verificationCode = await User.createRandomHash (new Date ().toString ());

		this.verifyCode = verificationCode;

		if (User.onRegisterInsert != null)
		{
			let user: User = await User.onRegisterInsert (this, hash, salt, verificationCode, verified);

			return (user);
		}

		let result: any = await db.queryOne (
			`INSERT INTO users (id, userType, firstName, lastName, email, password, passwordSalt, verifyCode, verified) 
			VALUES (UNHEX(REPLACE(UUID(),'-','')), ?, ?, ?, ?, ?, ?, ?, ?) returning id;`, 
			[this.userType, this.firstName, this.lastName, this.email, hash, salt, verificationCode, verified]);

		if (result.error != null)
			throw new Error (result.error);

		let idRaw: Buffer = result.results["id"];
		let userId: string = User.fromBinaryToUUID (idRaw);

		this.id = userId;

		return (this);
	}

	/**
	 * Get a user's logins. Intended for admin usage. 
	 * DOES NOT check any JWT tokens or any other user permissions.
	 */
	static async getUserLogins (db: HotDBMySQL, user: User, offset: number = 0, limit: number = 1): Promise<any[]>
	{
		let result: any = await db.query (
			`SELECT HEX(id) as id, HEX(userId) as userId, ip, loginDate, logOutDate 
			FROM userLogins WHERE userId = UNHEX(REPLACE(?, '-', '')) ORDER BY 
			loginDate DESC LIMIT ${limit} OFFSET ${offset};`,
				[user.id]);

		if (result.error != null)
			throw new Error (result.error);

		return (result.results);
	}

	/**
	 * Edit a user. Intended for admin usage. DOES NOT check any JWT tokens
	 * or any other user permissions.
	 */
	static async editUser (db: HotDBMySQL, user: User): Promise<void>
	{
		let result: any = await db.queryOne (
			`UPDATE users SET userType = ?, firstName = ?, lastName = ?, email = ?, verified = ? WHERE id = UNHEX(REPLACE(?, '-', ''));`,
			[user.userType, user.firstName, user.lastName, user.email, user.verified, user.id]);

		if (result.error != null)
			throw new Error (result.error);
	}

	/**
	 * Delete a user. Intended for admin usage. DOES NOT check any JWT tokens
	 * or any other user permissions.
	 */
	static async deleteUser (db: HotDBMySQL, user: User): Promise<void>
	{
		let result: any = await db.queryOne (
			`DELETE FROM users WHERE id = UNHEX(REPLACE(?, '-', ''));`,
			[user.id]);

		if (result.error != null)
			throw new Error (result.error);
	}

	/**
	 * Have a user authenticate and login.
	 * 
	 * @param db The connected database.
	 * @param ip The IP address of the user. If this is a User object, it will not 
	 * retreive the user from the database and instead use the user object provided.
	 * @param email The user's email.
	 * @param password The user's password.
	 * @param getPassword If set to true, this will return the user's password and salt.
	 * ONLY USE THIS WHEN NECESSARY. I HAVE NO IDEA WHY THIS WOULD EVER BE NECESSARY, 
	 * BUT I'M PUTTING IT HERE JUST IN CASE.
	 */
	static async login (db: HotDBMySQL, ip: string | User, email?: string, 
		password?: string, getPassword: boolean = false): Promise<User>
	{
		let foundUser: User = null;

		if (typeof (ip) === "string")
			foundUser = await User.getUser (db, email, true);
		else
			foundUser = ip;

		if (foundUser == null)
			throw new Error (`Wrong email or password.`);

		if (foundUser.enabled === false)
			throw new Error (`This account has been disabled.`);

		if (foundUser.verified === false)
			throw new Error (`This account has not been verified yet.`);

		if (typeof (ip) === "string")
			foundUser.ip = ip;

		const cmp: boolean = await bcrypt.compare (password, foundUser.password);

		if (cmp === false)
			throw new Error (`Wrong email or password.`);

		let regenPassword: boolean = true;

		if (process.env["DISABLE_REHASHING"] != null)
		{
			if (process.env["DISABLE_REHASHING"] === "1")
				regenPassword = false;
		}

		if (regenPassword === true)
		{
			const salt: string = await User.generateSalt ();
			const hash: string = await User.generateHash (password, salt);

			if (User.onLoginRegenPasswordUpdate != null)
				await User.onLoginRegenPasswordUpdate (foundUser, hash, salt);
			else
			{
				let result = await db.query (`update users set password = ?, passwordSalt = ? where email = ?`, 
												[hash, salt, email]);

				if (result.error != null)
					throw new Error (result.error);
			}
		}

		if (getPassword === false)
		{
			password = "";
			foundUser.password = "";
			foundUser.passwordSalt = "";

			delete foundUser.password;
			delete foundUser.passwordSalt;
		}

		let userLoginId: string = "";

		if (User.onLoginInsertUserLogin != null)
			userLoginId = await User.onLoginInsertUserLogin (foundUser, foundUser.ip);
		else
		{
			let result: any = await db.queryOne (
`INSERT INTO userLogins (id, userId, ip) VALUES (UNHEX(REPLACE(UUID(),'-','')), UNHEX(REPLACE(?,'-','')), ?) returning id;`, 
				[foundUser.id, ip]);

			if (result.error != null)
				throw new Error (result.error);

			let idRaw: Buffer = result.results["id"];
			userLoginId = User.fromBinaryToUUID (idRaw);
		}

		foundUser.jwtToken = await User.generateJWTToken ({ user: foundUser, ip: ip, userLoginId: userLoginId });

		return (foundUser);
	}

	/**
	 * Log out.
	 */
	static async logOut (db: HotDBMySQL, jwtToken: string): Promise<void>
	{
		let decoded: IJWTToken = await User.decodeJWTToken (jwtToken);
		let user: IUser = decoded.user;
		let userLoginId: string = decoded.userLoginId;

		User.invalidJWTTokens[jwtToken] = true;

		if (User.onLogoutUpdateUserLogin != null)
			await User.onLogoutUpdateUserLogin (user, userLoginId);
		else
		{
			let result = await db.query (
				`update userLogins set logOutDate = NOW() where id = UNHEX(REPLACE(?,'-',''))`, 
					[userLoginId]);

			if (result.error != null)
				throw new Error (result.error);
		}
	}

	/**
	 * Verify a user.
	 */
	static async verifyUser (db: HotDBMySQL, email: string, verificationCode: string): Promise<void>
	{
		let foundUser: User = await User.getUser (db, email, true);

		if (foundUser == null)
			throw new Error (`User not found.`);

		if (foundUser.verifyCode !== verificationCode)
			throw new Error (`Unable to verify user. Incorrect verification code.`);

		if (User.onVerifyUserUpdate != null)
			await User.onVerifyUserUpdate (foundUser);
		else
		{
			let result = await db.query (
				`update users set verified = 1 where email = ?`, 
					[email]);

			if (result.error != null)
				throw new Error (result.error);
		}
	}

	/**
	 * Start the reset of a user's password.
	 */
	static async forgotPassword (db: HotDBMySQL, email: string, emailConfig: EmailConfig = null): Promise<string>
	{
		let user: User = await User.getUser (db, email);

		if (user == null)
			throw new Error (`User not found.`);

		user.verifyCode = await User.createRandomHash (new Date ().toString ());

		if (User.onForgotPasswordUpdate != null)
			await User.onForgotPasswordUpdate (user);
		else
		{
			let result = await db.query (
				`update users set verifyCode = ? where id = ?`,
					[user.verifyCode, user.id]);

			if (result.error != null)
				throw new Error (result.error);
		}

		if (emailConfig != null)
		{
			const sesClientConfig: SESClientConfig = emailConfig.sesClientConfig;
			const client = new SESClient (sesClientConfig);
			const cmd = new SendEmailCommand ({
					Destination: {
						ToAddresses: [user.email]
					},
					Message: {
						Body: {
							Text: {
								Charset: "UTF-8",
								Data: emailConfig.body (user, user.verifyCode)
							}
						},
						Subject: {
							Charset: "UTF-8",
							Data: emailConfig.subject
						}
					},
					Source: emailConfig.fromAddress
				});
			const response = await client.send (cmd);
		}

		return (user.verifyCode);
	}

	/**
	 * Reset a user's password.
	 */
	static async resetForgottenPassword (db: HotDBMySQL, email: string, 
		verificationCode: string, newPassword: string): Promise<void>
	{
		let foundUser: User = await User.getUser (db, email);

		if (foundUser == null)
			throw new Error (`User not found.`);

		if (foundUser.verifyCode !== verificationCode)
			throw new Error (`Unable to reset password. Incorrect verification code.`);

		const salt: string = await User.generateSalt ();
		const hash: string = await User.generateHash (newPassword, salt);

		if (User.onResetForgottenPasswordUpdate != null)
			await User.onResetForgottenPasswordUpdate (foundUser, hash, salt);
		else
		{
			// Update the user's password in the database.
			let result = await db.query (
				`update users set password = ?, passwordSalt = ?, verifyCode = null where id = ?`,
					[hash, salt, foundUser.id]);

			if (result.error != null)
				throw new Error (result.error);
		}
	}

	/**
	 * Get user by their email. This WILL NOT return the current user's api key or secret.
	 * 
	 * @param getPassword If set to true, this will return the user's password and salt.
	 * ONLY USE THIS WHEN NECESSARY.
	 */
	static async getUser (db: HotDBMySQL, email: string, getPassword: boolean = false): Promise<User | null>
	{
		let rawDBResults: any = null;

		if (User.onGetUserSelect != null)
		{
			rawDBResults = await User.onGetUserSelect (email);

			if (rawDBResults == null)
				return (null);
		}
		else
		{
			let result: MySQLResults = await db.queryOne (`select * from users where email = ?;`, [email]);

			if (result == null)
				return (null);

			if (result.error != null)
				return (null);

			if (result.results == null)
				return (null);

			rawDBResults = result.results;
		}

		let userId: string = User.fromBinaryToUUID (rawDBResults["id"]);

		let user: User = new User ({
				id: userId,
				userType: rawDBResults["userType"],
				firstName: rawDBResults["firstName"],
				lastName: rawDBResults["lastName"],
				email: rawDBResults["email"],
				password: rawDBResults["password"],
				passwordSalt: rawDBResults["passwordSalt"],
				verifyCode: rawDBResults["verifyCode"],
				registeredDate: rawDBResults["registeredDate"],
				loginDate: rawDBResults["loginDate"],
				enabled: rawDBResults["enabled"], 
				verified: rawDBResults["verified"]
			});

		// Only get the password if explicitly told to do so.
		if (getPassword === false)
		{
			user.password = "";
			user.passwordSalt = "";
		}

		return (user);
	}

	/**
	 * Create a random hash.
	 */
	protected static async createRandomHash (salt: string, maxBytes: number = 10): Promise<string>
	{
		let finalResult: string = await new Promise ((resolve, reject) =>
			{
				crypto.randomBytes (maxBytes, (err: Error | null, buffer: Buffer) => 
					{
						let msg: string = buffer.toString ("hex");
						let result: string = crypto.createHmac ("sha256", salt).update (msg).digest ("hex");

						resolve (result);
					});
			});

		return (finalResult);
	}

	/**
	 * Generate a JWT Token.
	 */
	static async generateJWTToken (jsonObj: any, expiresIn: string = "30 days"): Promise<string>
	{
		if (User.jwtSecretKey === "")
			throw new Error (`A JWT secret key is required to run!`);

		return (new Promise<string> ((resolve, reject) =>
			{
				const finalJSONObj = JSON.parse (JSON.stringify (jsonObj));

				jwt.sign (finalJSONObj, User.jwtSecretKey, { expiresIn: expiresIn }, (err: Error, encoded: string) =>
					{
						if (err != null)
							throw err;

						resolve (encoded);
					});
			}));
	}

	/**
	 * Verify and decode a JWT Token.
	 */
	static async decodeJWTToken (jwtToken: string): Promise<any>
	{
		if (User.jwtSecretKey === "")
			throw new Error (`A JWT secret key is required to run!`);

		if (User.invalidJWTTokens[jwtToken] != null)
		{
			if (User.invalidJWTTokens[jwtToken] === true)
				throw new Error (`JWT token has been invalidated!`);
		}

		return (new Promise<string> ((resolve, reject) =>
			{
				jwt.verify (jwtToken, User.jwtSecretKey, (err: Error, decoded: string) =>
					{
						if (err != null)
							throw new Error (`Unable to verify JWT token!`);

						resolve (decoded);
					});
			}));
	}
}