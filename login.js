import { DynamoDBClient, QueryCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { createHash, createHmac, randomBytes } from "crypto";

const client = new DynamoDBClient({});
const USERS_TABLE = process.env.USERS_TABLE;
const TOKENS_TABLE = process.env.TOKENS_TABLE;

// --- Helpers de Seguridad ---

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  const newHash = createHash("sha256").update(salt + password).digest("hex");
  return newHash === hash;
}

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function signJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const headerEnc = base64url(JSON.stringify(header));
  const payloadEnc = base64url(JSON.stringify(payload));
  const data = `${headerEnc}.${payloadEnc}`;
  
  const signature = createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${data}.${signature}`;
}

// --- Handler Principal ---

export const handler = async (event) => {
  try {
    const body = JSON.parse(event.body);
    const { user_id, password } = body;

    // 1. Buscar usuario en DynamoDB
    const res = await client.send(new QueryCommand({
        TableName: USERS_TABLE,
        KeyConditionExpression: "user_id = :u",
        ExpressionAttributeValues: { ":u": { S: user_id } }
    }));

    if (!res.Items || res.Items.length === 0) {
      return { statusCode: 401, body: JSON.stringify({ message: "Usuario no encontrado" }) };
    }

    const user = res.Items[0];

    // 2. Validar contraseña
    const isValid = verifyPassword(password, user.password.S);
    if (!isValid) {
      return { statusCode: 401, body: JSON.stringify({ message: "Credenciales inválidas" }) };
    }

    // 3. Generar Token JWT
    const expirationTime = Math.floor(Date.now() / 1000) + 3600; // 1 hora
    const token = signJWT(
      { user_id: user.user_id.S, exp: expirationTime },
      process.env.JWT_SECRET
    );

    // 4. (Opcional según diagrama) Guardar token en t_tokens_acceso para seguimiento
    try {
        await client.send(new PutItemCommand({
            TableName: TOKENS_TABLE,
            Item: {
                token: { S: token },
                expires: { S: new Date(expirationTime * 1000).toISOString() },
                user_id: { S: user_id }
            }
        }));
    } catch (dbErr) {
        console.warn("No se pudo guardar el token en la tabla, pero se retornará al usuario.", dbErr);
    }

    return {
        statusCode: 200,
        body: JSON.stringify({ 
            message: "Login exitoso",
            token: token 
        }) 
    };

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return { statusCode: 500, body: JSON.stringify({ message: "Error del servidor" }) };
  }
};
