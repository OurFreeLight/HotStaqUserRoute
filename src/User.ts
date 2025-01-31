import { MySQLResults, HotDBType, HotDB } from "hotstaq";
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
	 * The user's display name.
	 */
	displayName?: string;
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
	subject?: string;
	/**
	 * The from address. Where the email is being sent from.
	 */
	fromAddress: string;
	/**
	 * The body of the email to send.
	 */
	body?: (user: IUser, verificationCode: string) => string;
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
	 * The user's display name.
	 */
	displayName: string;
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
	 * The minimum length of an email.
	 */
	static minEmailLength: number = 3;
	/**
	 * The maximum length of an email.
	 */
	static maxEmailLength: number = 32;
	/**
	 * The minimum length of a password.
	 */
	static minPasswordLength: number = 5;
	/**
	 * The maximum length of a password.
	 */
	static maxPasswordLength: number = 32;
	/**
	 * The regex to use to check for a valid email. If emailValidateRegEx is 
	 * set to null, this will not be used.
	 */
	static emailValidateRegEx: RegExp = /\S+@\S+\.\S+/;
	/**
	 * The minimum length of a display name.
	 */
	static minDisplayNameLength: number = 0;
	/**
	 * The maximum length of a display name.
	 */
	static maxDisplayNameLength: number = 32;
	/**
	 * The regex to use to check for a valid display name. If displayNameValidateRegEx is
	 * set to null, this will not be used.
	 */
	static displayNameValidateRegEx: RegExp = /^[A-Za-z0-9_]+$/;
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
	 * The event to fire when a user has successfully logged in, and the 
	 * JWT token needs to be generated to be passed to the end user.
	 */
	static onLoginGenerateJWTToken: (user: User, ip: string, userId: string) => Promise<string> = null;
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
	 * The event to fire when a user's email verification has been sent. If a result 
	 * other than null or undefined is returned, this will be used as the email config.
	 */
	static onVerificationSent: (user: User, emailConfig: EmailConfig) => Promise<EmailConfig> = null;
	/**
	 * The event to fire when a user's forgotten password has started. This updates 
	 * the user's verifyCode in the database so the user can update their password.
	 */
	static onForgotPasswordUpdate: (user: User) => Promise<void> = null;
	/**
	 * The event to fire when a user's password has changed. This updates 
	 * the user's new password hash and salt in the database.
	 */
	static onChangePasswordUpdate: (user: User, 
		passwordHash: string, passwordSalt: string) => Promise<void> = null;
	/**
	 * The event to fire when a user's forgotten password has been reset. This updates 
	 * the user's new password hash and salt in the database.
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
		this.enabled = user.enabled ?? true;
		this.id = user.id || "";
		this.userType = user.userType || "user";
		this.displayName = user.displayName || "";
		this.firstName = user.firstName || "";
		this.lastName = user.lastName || "";
		this.email = user.email || "";
		this.password = user.password || "";
		this.passwordSalt = user.passwordSalt || "";
		this.verifyCode = user.verifyCode || "";
		this.registeredDate = user.registeredDate || null;
		this.loginDate = user.loginDate || null
		this.verified = user.verified ?? false;
		this.ip = user.ip || "";
		this.jwtToken = user.jwtToken || "";
	}

	/**
	 * Sync the table. This will create the tables if they do not already exist.
	 */
	static async syncTables (db: HotDB, debug: boolean): Promise<void>
	{
		if (db == null)
			throw new Error ("UserRoute: Database is not connected");

		if ((db.type === HotDBType.MySQL) || (db.type === HotDBType.MariaDB))
		{
			await db.query (
				`create table if not exists users (
					id                BINARY(16)     NOT NULL,
					user_type         VARCHAR(256)   DEFAULT 'user',
					display_name      VARCHAR(256)   DEFAULT '',
					first_name        VARCHAR(256)   DEFAULT '',
					last_name         VARCHAR(256)   DEFAULT '',
					email             VARCHAR(256)   DEFAULT '',
					password_hash     VARCHAR(256)   DEFAULT '',
					password_salt     VARCHAR(256)   DEFAULT '',
					verify_code       VARCHAR(256)   DEFAULT '',
					verified          TINYINT(1)     DEFAULT '0',
					registered_date   DATETIME       DEFAULT NOW(),
					deletion_date     DATETIME       DEFAULT NULL,
					enabled           TINYINT(1)     DEFAULT '1',
					PRIMARY KEY (id)
				)`);
			await db.query (
				`create table if not exists user_logins (
					id                BINARY(16)     NOT NULL,
					user_id           BINARY(16)     DEFAULT '',
					ip                VARCHAR(256)   DEFAULT '',
					login_date        DATETIME       DEFAULT NOW(),
					log_out_date      DATETIME       DEFAULT NULL,
					PRIMARY KEY (id)
				)`);
		}

		if (db.type === HotDBType.Postgres)
		{
			await db.query (
				`create table if not exists users (
					id                UUID           NOT NULL,
					user_type         VARCHAR(256)   DEFAULT 'user',
					display_name      VARCHAR(256)   DEFAULT '',
					first_name        VARCHAR(256)   DEFAULT '',
					last_name         VARCHAR(256)   DEFAULT '',
					email             VARCHAR(256)   DEFAULT '',
					password_hash     VARCHAR(256)   DEFAULT '',
					password_salt     VARCHAR(256)   DEFAULT '',
					verify_code       VARCHAR(256)   DEFAULT '',
					verified          SMALLINT       DEFAULT '0',
					registered_date   TIMESTAMP      DEFAULT NOW(),
					deletion_date     TIMESTAMP      DEFAULT NULL,
					enabled           SMALLINT       DEFAULT '1',
					PRIMARY KEY (id)
				)`);
			await db.query (
				`create table if not exists user_logins (
					id                UUID           NOT NULL,
					user_id           UUID           DEFAULT NULL,
					ip                VARCHAR(256)   DEFAULT '',
					login_date        TIMESTAMP      DEFAULT NOW(),
					log_out_date      TIMESTAMP      DEFAULT NULL,
					PRIMARY KEY (id)
				)`);
		}
	}

	/**
	 * Checks if the users table is empty.
	 * 
	 * This performs a select on the users table.
	 * 
	 * @returns Returns true if the users table is empty.
	 */
	static async checkForEmptyUsers (db: HotDB): Promise<boolean>
	{
		let results: MySQLResults = await db.queryOne (`select COUNT(*) from users;`);

		if (results.error != null)
			throw new Error (results.error);

		if (results.results["COUNT(*)"] < 1)
			return (true);

		return (false);
	}

	/**
	 * Seed the users table. This performs an insert for multiple users on the users table.
	 * 
	 * @param testPlayers The test players to seed. If the array is empty, it will use the default test players.
	 */
	static async seedUsers (db: HotDB, testPlayers: User[] = []): Promise<void>
	{
		if (testPlayers.length < 1)
		{
			testPlayers = [
					new User ({
						firstName: "John",
						lastName: "Doe",
						displayName: "Test1",
						email: "test1@freelight.org",
						password: "a867h398jdg",
						verified: true
					}),
					new User ({
						firstName: "Jane",
						lastName: "Smith",
						displayName: "Test2",
						email: "test2@freelight.org",
						password: "ai97w3a98w3498",
						verified: true }),
					new User ({
						userType: "admin",
						firstName: "Bob",
						lastName: "Derp",
						displayName: "Admin1",
						email: "admin1@freelight.org",
						password: "a98j3w987aw3h47u",
						verified: true })
				];
		}

		for (let iIdx = 0; iIdx < testPlayers.length; iIdx++)
		{
			let testPlayer = testPlayers[iIdx];

			await testPlayer.register (db);
		}
	}

	/**
	 * Check if this is a valid email.
	 */
	public static validateEmail (email: string): boolean
	{
		if (email.length < User.minEmailLength)
			return (false);

		if (email.length >= User.maxEmailLength)
			return (false);

		const re: RegExp = User.emailValidateRegEx;

		return (re.test (email));
	}

	/**
	 * Check if the display name is valid.
	 */
	public static validateDisplayName (displayName: string): boolean
	{
		if (User.minDisplayNameLength === 0)
		{
			if (displayName.length === 0)
				return (true);
		}

		if (displayName.length < User.minDisplayNameLength)
			return (false);

		if (displayName.length >= User.maxDisplayNameLength)
			return (false);

		const re: RegExp = User.displayNameValidateRegEx;

		return (re.test (displayName));
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
	 * 
	 * @param buffer The UUID buffer to convert into a string. If the buffer is a string, this 
	 * will assume that the string is already a UUID and return it as is.
	 */
	static fromBinaryToUUID (buffer: Buffer | string): string
	{
		if (typeof (buffer) === "string")
			return (buffer);

		const hex: string = buffer.toString ('hex');
		return `${hex.substr (0, 8)}-${hex.substr (8, 4)}-${hex.substr (12, 4)}-${hex.substr (16, 4)}-${hex.substr (20)}`;
	}

	/**
	 * Get a register query.
	 */
	protected static getRegisterQuery (dbtype: HotDBType): string
	{
		let query: string = "";

		if (dbtype === HotDBType.MySQL)
		{
			query = `
			SET @generated_id = UNHEX(REPLACE(UUID(), '-', ''));

			INSERT INTO users (id, user_type, display_name, first_name, last_name, email, password_hash, password_salt, verify_code, verified, enabled) 
			VALUES (@generated_id, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

			SELECT @generated_id AS id;`;
		}

		if (dbtype === HotDBType.MariaDB)
		{
			query = `
			INSERT INTO users (id, user_type, display_name, first_name, last_name, email, password_hash, password_salt, verify_code, verified, enabled) 
			VALUES (UNHEX(REPLACE(UUID(),'-','')), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) returning id;`;
		}

		if (dbtype === HotDBType.Postgres)
		{
			query = `
			INSERT INTO users (id, user_type, display_name, first_name, last_name, email, password_hash, password_salt, verify_code, verified, enabled) 
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10) returning id;`;
		}

		return (query);
	}

	/**
	 * Register a user. This will perform an insert on the users table.
	 */
	async register (db: HotDB, emailConfig: EmailConfig = null, verifyCode: string = ""): Promise<User>
	{
		this.email = this.email.toLowerCase ();

		if (User.emailValidateRegEx != null)
		{
			if (User.validateEmail (this.email) === false)
				throw new Error (`Invalid email.`);
		}

		if (User.displayNameValidateRegEx != null)
		{
			if (User.validateDisplayName (this.displayName) === false)
				throw new Error (`Invalid display name.`);
		}

		if (User.minPasswordLength != null)
		{
			if (this.password.length < User.minPasswordLength)
				throw new Error (`Password is too short. Must be at least ${User.minPasswordLength} characters.`);
		}

		if (User.maxPasswordLength != null)
		{
			if (this.password.length >= User.maxPasswordLength)
				throw new Error (`Password is too long. Must be less than ${User.maxPasswordLength} characters.`);
		}

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

		if (verifyCode !== "")
			verificationCode = verifyCode;

		if (verified === 0)
		{
			if (verifyCode !== "")
				verificationCode = verifyCode;
			else
				verificationCode = await User.createRandomHash (new Date ().toString ());
		}

		this.verifyCode = verificationCode;

		if (User.onRegisterInsert != null)
		{
			let user: User = await User.onRegisterInsert (this, hash, salt, verificationCode, verified);

			return (user);
		}

		let enabled = 1;

		if (this.enabled === false)
			enabled = 0;

		let query = User.getRegisterQuery (db.type);

		let result: any = await db.queryOne (query, 
			[this.userType, this.displayName, this.firstName, this.lastName, this.email, hash, salt, this.verifyCode, verified, enabled]);

		if (result.error != null)
			throw new Error (result.error);

		let idRaw: Buffer = result.results["id"];
		let userId: string = User.fromBinaryToUUID (idRaw);

		this.id = userId;

		if (emailConfig != null)
		{
			const body: string = emailConfig.body (this, this.verifyCode);

			await User.sendEmail (this.email, emailConfig.subject, body, emailConfig);
		}

		return (this);
	}

	/**
	 * Get a user login query.
	 */
	protected static getUserLoginsQuery (dbtype: HotDBType, limit: number, offset: number): string
	{
		let query: string = "";

		if ((dbtype === HotDBType.MySQL) || (dbtype === HotDBType.MariaDB))
		{
			query = `SELECT HEX(id) as id, HEX(user_id) as user_id, ip, login_date, log_out_date 
			FROM user_logins WHERE user_id = UNHEX(REPLACE(?, '-', '')) ORDER BY 
			login_date DESC LIMIT ${limit} OFFSET ${offset};`;
		}

		if (dbtype === HotDBType.Postgres)
		{
			query = `SELECT id, user_id, ip, login_date, log_out_date 
			FROM user_logins WHERE user_id = $1::uuid ORDER BY 
			login_date DESC LIMIT ${limit} OFFSET ${offset};`;
		}

		return (query);
	}


	/**
	 * Get a user's logins. Intended for admin usage. 
	 * DOES NOT check any JWT tokens or any other user permissions.
	 * 
	 * This will perform a select on the user_logins table.
	 */
	static async getUserLogins (db: HotDB, user: User, offset: number = 0, limit: number = 1): Promise<any[]>
	{
		let result: any = await db.query (User.getUserLoginsQuery (db.type, limit, offset), [user.id]);

		if (result.error != null)
			throw new Error (result.error);

		return (result.results);
	}

	/**
	 * Edit a user. Intended for admin usage or the user trying to edit their account. THIS DOES NOT check any JWT tokens
	 * or any other user permissions.
	 * 
	 * This updates the users table.
	 */
	static async editUser (db: HotDB, user: IUser): Promise<void>
	{
		let keyValues: string = "";
		let counter: number = 0;
		let values: any[] = [];

		if (db.type === HotDBType.Postgres)
			counter = 1;

		if (user.userType != null)
		{
			if (counter === 0)
				keyValues += `user_type = ?,`;
			else
				keyValues += `user_type = $${counter},`;

			values.push (user.userType);
			counter++;
		}

		if (user.displayName != null)
		{
			if (counter === 0)
				keyValues += `display_name = ?,`;
			else
				keyValues += `display_name = $${counter},`;

			values.push (user.displayName);
			counter++;
		}

		if (user.firstName != null)
		{
			if (counter === 0)
				keyValues += `first_name = ?,`;
			else
				keyValues += `first_name = $${counter},`;

			values.push (user.firstName);
		}

		if (user.lastName != null)
		{
			if (counter === 0)
				keyValues += `last_name = ?,`;
			else
				keyValues += `last_name = $${counter},`;

			values.push (user.lastName);
			counter++;
		}

		if (user.email != null)
		{
			if (counter === 0)
				keyValues += `email = ?,`;
			else
				keyValues += `email = $${counter},`;

			values.push (user.email);
			counter++;
		}

		if (user.verified != null)
		{
			let verified = 1;

			if (user.verified === false)
				verified = 0;

			if (counter === 0)
				keyValues += `verified = ?,`;
			else
				keyValues += `verified = $${counter},`;

			values.push (verified);
			counter++;
		}

		if (user.enabled != null)
		{
			let enabled = 1;

			if (user.enabled === false)
				enabled = 0;

			if (counter === 0)
				keyValues += `enabled = ?,`;
			else
				keyValues += `enabled = $${counter},`;

			values.push (enabled);
			counter++;
		}

		if (keyValues !== "")
		{
			keyValues = keyValues.substr (0, keyValues.length - 1);

			values.push (user.id);

			let idpart = `UNHEX(REPLACE(?, '-', ''))`;

			if (db.type === HotDBType.Postgres)
				idpart = `$${counter}::uuid`;

			let result: any = await db.queryOne (
				`UPDATE users SET ${keyValues} WHERE id = ${idpart};`,
				values);

			if (result.error != null)
				throw new Error (result.error);
		}
	}

	/**
	 * Delete a user. Intended for admin usage. DOES NOT check any JWT tokens
	 * or any other user permissions.
	 * 
	 * This performs a delete on the users table.
	 */
	static async deleteUser (db: HotDB, user: User): Promise<void>
	{
		let query = `DELETE FROM users WHERE id = UNHEX(REPLACE(?, '-', ''));`;

		if (db.type === HotDBType.Postgres)
			query = `DELETE FROM users WHERE id = $1::uuid;`;

		let result: any = await db.queryOne (query, [user.id]);

		if (result.error != null)
			throw new Error (result.error);
	}

	/**
	 * Have a user authenticate and login.
	 * 
	 * This performs a select on the users table and an insert on the user_logins table.
	 * 
	 * @param db The connected database.
	 * @param ip The IP address of the user. If this is a User object, it will not 
	 * retreive the user from the database and instead use the user object provided.
	 * @param email The user's email.
	 * @param password The user's password.
	 * @param getPassword If set to true, this will return the user's password, salt, and verifyCode.
	 * ONLY USE THIS WHEN NECESSARY. I HAVE NO IDEA WHY THIS WOULD EVER BE NECESSARY, BUT I'M PUTTING 
	 * IT HERE JUST IN CASE.
	 */
	static async login (db: HotDB, ip: string | User, email?: string, 
		password?: string, getPassword: boolean = false): Promise<User>
	{
		let foundUser: User = null;

		if (User.minPasswordLength != null)
		{
			if (password.length < User.minPasswordLength)
				throw new Error (`Password is too short. Must be at least ${User.minPasswordLength} characters.`);
		}

		if (User.maxPasswordLength != null)
		{
			if (password.length >= User.maxPasswordLength)
				throw new Error (`Password is too long. Must be less than ${User.maxPasswordLength} characters.`);
		}

		if (typeof (ip) === "string")
		{
			email = email.toLowerCase ();

			foundUser = await User.getUser (db, email, true);
		}
		else
		{
			foundUser = ip;
			foundUser.email = foundUser.email.toLowerCase ();
		}

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
				let query = `update users set password_hash = ?, password_salt = ? where email = ?`;

				if (db.type === HotDBType.Postgres)
					query = `update users set password_hash = $1, password_salt = $2 where email = $3`;

				let result = await db.query (query, [hash, salt, email]);

				if (result.error != null)
					throw new Error (result.error);
			}
		}

		if (getPassword === false)
		{
			password = "";
			foundUser.password = "";
			foundUser.passwordSalt = "";
			foundUser.verifyCode = "";

			delete foundUser.password;
			delete foundUser.passwordSalt;
			delete foundUser.verifyCode;
		}

		let userLoginId: string = "";

		if (User.onLoginInsertUserLogin != null)
			userLoginId = await User.onLoginInsertUserLogin (foundUser, foundUser.ip);
		else
		{
			let query = "";

			if (db.type === HotDBType.MySQL)
			{
				query =
			`
			SET @generated_id = UNHEX(REPLACE(UUID(), '-', ''));
			INSERT INTO user_logins (id, user_id, ip) VALUES (@generated_id, UNHEX(REPLACE(?,'-','')), ?);
			SELECT @generated_id AS id;
			`;
			}

			if (db.type === HotDBType.MariaDB)
			{
				query =
			`INSERT INTO user_logins (id, user_id, ip) VALUES (UNHEX(REPLACE(UUID(),'-','')), UNHEX(REPLACE(?,'-','')), ?) returning id;`;
			}

			if (db.type === HotDBType.Postgres)
				query = `INSERT INTO user_logins (id, user_id, ip) VALUES (gen_random_uuid(), $1, $2) returning id;`;

			let result: any = await db.queryOne (query, [foundUser.id, ip]);

			if (result.error != null)
				throw new Error (result.error);

			let idRaw: Buffer = result.results["id"];
			userLoginId = User.fromBinaryToUUID (idRaw);
		}

		if (User.onLoginGenerateJWTToken != null)
			foundUser.jwtToken = await User.onLoginGenerateJWTToken (foundUser, foundUser.ip, userLoginId);
		else
			foundUser.jwtToken = await User.generateJWTToken ({ user: foundUser, ip: ip, userLoginId: userLoginId });

		return (foundUser);
	}

	/**
	 * Log out.
	 * 
	 * This performs an update on the user_logins table.
	 */
	static async logOut (db: HotDB, jwtToken: string): Promise<void>
	{
		let decoded: IJWTToken = await User.decodeJWTToken (jwtToken);
		let user: IUser = decoded.user;
		let userLoginId: string = decoded.userLoginId;

		User.invalidJWTTokens[jwtToken] = true;

		if (User.onLogoutUpdateUserLogin != null)
			await User.onLogoutUpdateUserLogin (user, userLoginId);
		else
		{
			let query = `update user_logins set log_out_date = NOW() where id = UNHEX(REPLACE(?,'-',''))`;

			if (db.type === HotDBType.Postgres)
				query = `update user_logins set log_out_date = NOW() where id = $1::uuid`;

			let result = await db.query (query, [userLoginId]);

			if (result.error != null)
				throw new Error (result.error);
		}
	}

	/**
	 * Verify a user.
	 * 
	 * This performs an update on the users table.
	 */
	static async verifyUser (db: HotDB, email: string, verificationCode: string): Promise<void>
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
			let query = `update users set verified = 1 where email = ?`;

			if (db.type === HotDBType.Postgres)
				query = `update users set verified = 1 where email = $1`;

			let result = await db.query (query, [email]);

			if (result.error != null)
				throw new Error (result.error);
		}
	}

	/**
	 * Change password.
	 * 
	 * This performs an update on the users table.
	 */
	static async changePassword (db: HotDB, user: User, newPassword: string): Promise<void>
	{
		if (newPassword === "")
			throw new Error (`New password cannot be empty!`);

		if (user.id === "")
			throw new Error (`No user id supplied!`);

		if (User.minPasswordLength != null)
		{
			if (newPassword.length < User.minPasswordLength)
				throw new Error (`Password is too short. Must be at least ${User.minPasswordLength} characters.`);
		}

		if (User.maxPasswordLength != null)
		{
			if (newPassword.length >= User.maxPasswordLength)
				throw new Error (`Password is too long. Must be less than ${User.maxPasswordLength} characters.`);
		}

		const salt: string = await User.generateSalt ();
		const hash: string = await User.generateHash (newPassword, salt);

		if (User.onChangePasswordUpdate != null)
			await User.onChangePasswordUpdate (user, hash, salt);
		else
		{
			let query = `update users set password_hash = ?, password_salt = ?, verify_code = null where id = UNHEX(REPLACE(?,'-',''))`;

			if (db.type === HotDBType.Postgres)
				query = `update users set password_hash = $1, password_salt = $2, verify_code = null where id = $3::uuid`;

			// Update the user's password in the database.
			let result = await db.query (query, [hash, salt, user.id]);

			if (result.error != null)
				throw new Error (result.error);
		}
	}

	/**
	 * Send the verification email.
	 */
	static async sendVerificationEmail (user: User, emailConfig: EmailConfig): Promise<void>
	{
		if (User.onVerificationSent != null)
		{
			let result = await User.onVerificationSent (user, emailConfig);

			if (result != null)
				emailConfig = result;
		}

		const body: string = emailConfig.body (user, user.verifyCode);

		await User.sendEmail (user.email, emailConfig.subject, body, emailConfig);
	}

	/**
	 * Start the reset of a user's password.
	 * 
	 * This performs an update on the users table.
	 */
	static async forgotPassword (db: HotDB, email: string, emailConfig: EmailConfig = null, verifyCode: string = ""): Promise<string>
	{
		let user: User = await User.getUser (db, email, true);

		if (user == null)
			throw new Error (`User not found.`);

		if (verifyCode !== "")
			user.verifyCode = verifyCode;
		else
			user.verifyCode = await User.createRandomHash (new Date ().toString ());

		if (User.onForgotPasswordUpdate != null)
			await User.onForgotPasswordUpdate (user);
		else
		{
			let query = `update users set verify_code = ? where id = UNHEX(REPLACE(?,'-',''))`;

			if (db.type === HotDBType.Postgres)
				query = `update users set verify_code = $1 where id = $2::uuid`;

			let result = await db.query (query, [user.verifyCode, user.id]);

			if (result.error != null)
				throw new Error (result.error);
		}

		if (emailConfig != null)
		{
			const body: string = emailConfig.body (user, user.verifyCode);

			await User.sendEmail (user.email, emailConfig.subject, body, emailConfig);
		}

		return (user.verifyCode);
	}

	/**
	 * Reset a user's password.
	 * 
	 * This performs an update on the users table.
	 */
	static async resetForgottenPassword (db: HotDB, email: string, 
		verificationCode: string, newPassword: string): Promise<void>
	{
		let foundUser: User = await User.getUser (db, email, true);

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
			let query = `update users set password_hash = ?, password_salt = ?, verify_code = null where id = UNHEX(REPLACE(?,'-',''))`;

			if (db.type === HotDBType.Postgres)
				query = `update users set password_hash = $1, password_salt = $2, verify_code = null where id = $3::uuid`;

			// Update the user's password in the database.
			let result = await db.query (query, [hash, salt, foundUser.id]);

			if (result.error != null)
				throw new Error (result.error);
		}
	}

	/**
	 * Send an email.
	 */
	static async sendEmail (toEmail: string, subject: string, body: string, emailConfig: EmailConfig): Promise<void>
	{
		const sesClientConfig: SESClientConfig = emailConfig.sesClientConfig;
		const client = new SESClient (sesClientConfig);
		const cmd = new SendEmailCommand ({
				Destination: {
					ToAddresses: [toEmail]
				},
				Message: {
					Body: {
						Text: {
							Charset: "UTF-8",
							Data: body
						}
					},
					Subject: {
						Charset: "UTF-8",
						Data: subject
					}
				},
				Source: emailConfig.fromAddress
			});
		const response = await client.send (cmd);
	}

	/**
	 * Get a user from a database result.
	 */
	static getUserFromResult (result: any, getPassword: boolean = false): User
	{
		let userId: string = User.fromBinaryToUUID (result["id"]);

		let user: User = new User ({
				id: userId,
				userType: result["user_type"],
				displayName: result["display_name"],
				firstName: result["first_name"],
				lastName: result["last_name"],
				email: result["email"],
				password: result["password_hash"],
				passwordSalt: result["password_salt"],
				verifyCode: result["verify_code"],
				registeredDate: new Date (result["registered_date"]),
				loginDate: new Date (result["login_date"]),
				enabled: true, 
				verified: true
			});

		if ((result["enabled"] === 0) || (result["enabled"] === false))
			user.enabled = false;

		if ((result["verified"] === 0) || (result["verified"] === false))
			user.verified = false;

		// Only get the password/verify code if explicitly told to do so.
		if (getPassword === false)
		{
			user.password = "";
			user.passwordSalt = "";
			user.verifyCode = "";
		}

		return (user);
	}

	/**
	 * Get user by their email. This WILL NOT return the current user's api key or secret.
	 * 
	 * This performs a select on the users table.
	 * 
	 * @param getPassword If set to true, this will return the user's password, salt, and verifyCode.
	 * ONLY USE THIS WHEN NECESSARY.
	 */
	static async getUser (db: HotDB, email: string, getPassword: boolean = false): Promise<User | null>
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
			let query = `select * from users where email = ?;`;

			if (db.type === HotDBType.Postgres)
				query = `select * from users where email = $1;`;

			let result: MySQLResults = await db.queryOne (query, [email]);

			if (result == null)
				return (null);

			if (result.error != null)
				return (null);

			if (result.results == null)
				return (null);

			rawDBResults = result.results;
		}

		let user: User = User.getUserFromResult (rawDBResults, getPassword);

		return (user);
	}

	/**
	 * Get user by their by. This WILL NOT return the current user's api key or secret.
	 * 
	 * This performs a select on the users table.
	 * 
	 * @param getPassword If set to true, this will return the user's password, salt, and verifyCode.
	 * ONLY USE THIS WHEN NECESSARY.
	 */
	static async getUserById (db: HotDB, id: string, getPassword: boolean = false): Promise<User | null>
	{
		let rawDBResults: any = null;

		if (User.onGetUserSelect != null)
		{
			rawDBResults = await User.onGetUserSelect (id);

			if (rawDBResults == null)
				return (null);
		}
		else
		{
			let query = `select * from users where id = ?;`;

			if (db.type === HotDBType.Postgres)
				query = `select * from users where id = $1;`;

			let result: MySQLResults = await db.queryOne (query, [id]);

			if (result == null)
				return (null);

			if (result.error != null)
				return (null);

			if (result.results == null)
				return (null);

			rawDBResults = result.results;
		}

		let user: User = User.getUserFromResult (rawDBResults, getPassword);

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
	static async decodeJWTToken (jwtToken: string): Promise<IJWTToken>
	{
		if (User.jwtSecretKey === "")
			throw new Error (`A JWT secret key is required to run!`);

		if (User.invalidJWTTokens[jwtToken] != null)
		{
			if (User.invalidJWTTokens[jwtToken] === true)
				throw new Error (`JWT token has been invalidated!`);
		}

		return (new Promise<IJWTToken> ((resolve, reject) =>
			{
				jwt.verify (jwtToken, User.jwtSecretKey, (err: Error, decoded: IJWTToken) =>
					{
						if (err != null)
							throw new Error (`Unable to verify JWT token!`);

						resolve (decoded);
					});
			}));
	}
}