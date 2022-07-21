import { callHandlingUnexpectedErrors } from '../lib/unexpected-error';
import { EXIT_CODES } from './exit-codes';
import { ConsoleCat } from '@console-cat/sdk';

ConsoleCat.initialize({
  cliId: 'snyk-b96457fb-8457-4473-8251-0929e101c465',
  apiUrl: 'http://localhost:8080',
  packageJson: require('../../package.json'),
  debug: true,
});
/**
 * By using a dynamic import, we can add error handlers before evaluating any
 * further modules. This way, if a module has errors, it'll be caught and
 * handled as we expect.
 */
callHandlingUnexpectedErrors(async () => {
  const { main } = await import('./main');
  await main();
}, EXIT_CODES.ERROR);
