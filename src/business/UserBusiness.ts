import { UserInputDTO, LoginInputDTO } from "../model/User";
import { UserDatabase } from "../data/UserDatabase";
import { IdGenerator } from "../services/IdGenerator";
import { HashManager } from "../services/HashManager";
import { Authenticator } from "../services/Authenticator";
import { CustomError } from "./CustomError";

export class UserBusiness {

    async createUser(user: UserInputDTO) {
        try {
            if (!user.name) {
                throw new CustomError(401, "Please insert your name")
            }

            if (!user.email) {
                throw new CustomError(401, "Please insert your email")
            }

            if (!user.password) {
                throw new CustomError(401, "Please insert your password")
            }

            if (user.role !== "ADMIN" && user.role !== "NORMAL") {
                throw new CustomError(401, `Invalid role, please insert "ADMIN" or "NORMAL"`)
            }

            const idGenerator = new IdGenerator();
            const id = idGenerator.generate();

            const hashManager = new HashManager();
            const hashPassword = await hashManager.hash(user.password);

            const userDatabase = new UserDatabase();
            await userDatabase.createUser(id, user.email, user.name, hashPassword, user.role.toUpperCase());

            const authenticator = new Authenticator();
            const accessToken = authenticator.generateToken({ id, role: user.role });

            return accessToken;
        } catch (error) {
            throw new CustomError(error.statusCode, error.message)
        }
    }

    async getUserByEmail(user: LoginInputDTO) {
        try {
            const userDatabase = new UserDatabase();
            const userFromDB = await userDatabase.getUserByEmail(user.email);

            const hashManager = new HashManager();
            const hashCompare = await hashManager.compare(user.password, userFromDB.getPassword());

            const authenticator = new Authenticator();
            const accessToken = authenticator.generateToken({ id: userFromDB.getId(), role: userFromDB.getRole() });

            if (!hashCompare) {
                throw new CustomError(422, "Invalid Password!");
            }

            return accessToken;
        }catch(error){
            throw new CustomError(error.statusCode, error.message)
        }

        
    }
}