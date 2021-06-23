import cookie from 'cookie';
import type { Handle } from '@sveltejs/kit';
import { getSession, SESSION_NAME } from './routes/api/_utils';

export const handle: Handle = async ({ request, render }) => {
	const cookies = cookie.parse(request.headers.cookie || '');

	const user = await getSession(cookies[SESSION_NAME]);
	request.locals.user = user;
	request.locals.userid = user?.publicAddress;

	// TODO https://github.com/sveltejs/kit/issues/1046
	if (request.query.has('_method')) {
		request.method = request.query.get('_method').toUpperCase();
	}

	const response = await render(request);

	return response;
};
