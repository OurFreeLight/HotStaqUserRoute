import { HotDBMySQL, MySQLResults } from "hotstaq";
import * as crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

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
	protected static jwtSecretKey: string = process.env["JWT_SECRET_KEY"] || "";

	constructor (user: IUser = {})
	{
		this.enabled = user.enabled || true;
		this.id = user.id || "";
		this.firstName = user.firstName || "";
		this.lastName = user.lastName || "";
		this.email = user.email || "";
		this.password = user.password || "";
		this.passwordSalt = user.passwordSalt || "";
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
		await db.query (
			`create table if not exists users (
					id             BINARY(16)     NOT NULL,
					firstName      VARCHAR(256)   DEFAULT '',
					lastName       VARCHAR(256)   DEFAULT '',
					email          VARCHAR(256)   DEFAULT '',
					password       VARCHAR(256)   DEFAULT '',
					passwordSalt   VARCHAR(256)   DEFAULT '',
					verified       TINYINT(1)     DEFAULT '0',
					registeredDate DATETIME       DEFAULT NOW(),
					enabled        TINYINT(1)     DEFAULT '1',
					PRIMARY KEY (id)
				)`);

		if (debug == true)
		{
			let results: any = await db.queryOne (`select COUNT(*) from users;`);

			if (results["COUNT(*)"] < 1)
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
	 * 
	 * Taken from:
	 * https://github.com/odo-network/binary-uuid/blob/master/src/binary-uuid.ts
	 */
	static fromBinaryToUUID (buf: Buffer): string
	{
		return [
				buf.toString('hex', 4, 8),
				buf.toString('hex', 2, 4),
				buf.toString('hex', 0, 2),
				buf.toString('hex', 8, 10),
				buf.toString('hex', 10, 16),
			].join('-');
	}

	/**
	 * Register a user.
	 */
	async register (db: HotDBMySQL): Promise<{ userId: string; }>
	{
		let tempUser: User | null = await User.getUser (db, this.email);

		if (tempUser != null)
			throw new Error (`Email has already been used.`);

		const salt: string = await User.generateSalt ();
		const hash: string = await User.generateHash (this.password, salt);

		// For security purposes, clear the password.
		this.password = "";

		let verified: number = 0;

		if (this.verified === true)
			verified = 1;

		if (process.env["AUTO_VERIFY_USERS"] != null)
		{
			if (process.env["AUTO_VERIFY_USERS"] === "1")
				verified = 1;
		}

		let result: any = await db.query (
			`INSERT INTO users (id, firstName, lastName, email, password, passwordSalt, verified) VALUES (UUID(), ?, ?, ?, ?, ?) returning id;`, 
			[this.firstName, this.lastName, this.email, hash, salt, verified]);

		if (result.error != null)
			throw new Error (result.error);

		let idRaw: Buffer = result[0]["id"];
		let userId: string = User.fromBinaryToUUID (idRaw);

		return ({ userId: userId });
	}

	/**
	 * Login.
	 */
	static async login (db: HotDBMySQL, ip: string, email: string, password: string): Promise<User>
	{
		let foundUser: User = await User.getUser (db, email, true);

		if (foundUser == null)
			throw new Error (`Wrong email or password.`);

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

			let result = await db.query (`update users set password = ?, passwordSalt = ? where email = ?`, 
											[hash, salt, email]);

			if (result.error != null)
				throw new Error (result.error);
		}

		password = "";
		foundUser.password = "";
		foundUser.passwordSalt = "";

		delete foundUser.password;
		delete foundUser.passwordSalt;

		const dateStr: string = new Date ().toString ();
		foundUser.jwtToken = await User.generateJWTToken (foundUser);

		return (foundUser);
	}

	/**
	 * Get user. This WILL NOT return the current user's api key or secret.
	 */
	static async getUser (db: HotDBMySQL, email: string, getPassword: boolean = false): Promise<User | null>
	{
		let result = await db.queryOne (`select * from users where email = ?;`, [email]);

		if (result.error != null)
			return (null);

		if (result.results == null)
			return (null);

		let userId: string = User.fromBinaryToUUID (result.results["id"]);

		let user: User = new User ({
				id: userId,
				firstName: result.results["firstName"],
				lastName: result.results["lastName"],
				email: result.results["email"],
				password: result.results["password"],
				passwordSalt: result.results["passwordSalt"],
				registeredDate: result.results["registeredDate"],
				loginDate: result.results["loginDate"],
				enabled: result.results["enabled"], 
				verified: result.results["verified"]
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
	static async generateJWTToken (jsonObj: any): Promise<string>
	{
		if (User.jwtSecretKey === "")
			throw new Error (`A JWT secret key is required to run!`);

		return (new Promise<string> ((resolve, reject) =>
			{
				const finalJSONObj = JSON.parse (JSON.stringify (jsonObj));

				jwt.sign (finalJSONObj, User.jwtSecretKey, { expiresIn: "30 days" }, (err: Error, encoded: string) =>
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
	static async decodeJWTToken (token: string): Promise<any>
	{
		if (User.jwtSecretKey === "")
			throw new Error (`A JWT secret key is required to run!`);

		return (new Promise<string> ((resolve, reject) =>
			{
				jwt.verify (token, User.jwtSecretKey, (err: Error, decoded: string) =>
					{
						if (err != null)
							throw new Error (`Unable to verify JWT token!`);

						resolve (decoded);
					});
			}));
	}
}