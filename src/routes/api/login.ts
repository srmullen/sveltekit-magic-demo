import type { Request, Response } from '@sveltejs/kit';
import { magic } from './_magic';
import { createSessionCookie } from './_utils';

export async function post(req: Request): Promise<Response> {
  try {
    // Parse and validate the DID token
    const didToken = magic.utils.parseAuthorizationHeader(req.headers['authorization']);
    magic.token.validate(didToken);

    // Token is valid, so get the user metadata and set it in a cookie.
    const metadata = await magic.users.getMetadataByToken(didToken);
    const cookie = await createSessionCookie(metadata);

    return {
      status: 200,
      headers: {
        'set-cookie': cookie
      },
      body: {
        user: metadata
      }
    };
  } catch (err) {
    console.log(err);
    return {
      status: 500,
      body: {
        error: {
          message: 'Internal Server Error'
        }
      }
    };
  }
}
