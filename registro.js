import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { createHash, randomBytes } from "crypto";

const client = new DynamoDBClient({});
const USERS_TABLE = process.env.USERS_TABLE;

// Función para hashear el password con salt
function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = createHash("sha256").update(salt + password).digest("hex");
  return `${salt}:${hash}`;
}

export const handler = async (event) => {
  try {
    const body = JSON.parse(event.body);
    // El PDF especifica "user_id" y "password"
    const { user_id, password } = body;

    if (!user_id || !password) {
      return { statusCode: 400, body: JSON.stringify({ message: "Faltan campos requeridos" }) };
    }

    const hashedPassword = hashPassword(password);

    await client.send(new PutItemCommand({
        TableName: USERS_TABLE,
        Item: {
          user_id: { S: user_id },
          password: { S: hashedPassword }
        }
    }));

    return {
      statusCode: 200,
      body: JSON.stringify({ message: "Usuario registrado exitosamente", user_id }),
    };

  } catch (err) {
    console.error("Error en registro:", err);
    return { statusCode: 500, body: JSON.stringify({ message: "Error interno del servidor" }) };
  }
};
