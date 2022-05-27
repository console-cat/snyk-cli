import * as path from 'path';
import { fakeServer, FakeServer } from '../../../test/acceptance/fake-server';
import {
  createProjectFromWorkspace,
  TestProject,
} from '../../../test/jest/util/createProject';
import { startCommand, TestCLI } from '../../../test/jest/util/startSnykCLI';

jest.setTimeout(1000 * 60);

const dockerComposeFile = path.resolve(
  'test/fixtures/kerberos/docker-compose.yml',
);

async function startKerberosEnvironment(
  project: TestProject,
  proxyPort: number,
): Promise<TestCLI> {
  // Stop any orphaned containers from previous runs.
  await stopKerberosEnvironment();

  const dockerUp = await startCommand(
    'docker-compose',
    ['--file', dockerComposeFile, 'up', '--build'],
    {
      env: {
        ...process.env,
        HTTP_PROXY_PORT: `${proxyPort}`,
        PROJECT_PATH: project.path(),
      },
    },
  );
  await expect(dockerUp).toDisplay('Kerberos setup complete.', {
    timeout: 30_000,
  });
  return dockerUp;
}

async function stopKerberosEnvironment(): Promise<void> {
  const dockerDown = await startCommand('docker-compose', [
    '--file',
    dockerComposeFile,
    'down',
  ]);
  await expect(dockerDown).toExitWith(0, { timeout: 30_000 });
}

describe('kerberos', () => {
  if (!process.env.TEST_SNYK_COMMAND?.includes('linux')) {
    // eslint-disable-next-line jest/no-focused-tests
    it.only('Kerberos can only be tested against Linux builds.', () => {
      console.warn(
        'Skipping test. Kerberos can only be tested against Linux builds.',
      );
    });
  }

  let server: FakeServer;
  let env: Record<string, string>;
  let project: TestProject;
  let kerberosServer: TestCLI;

  beforeAll(async () => {
    project = await createProjectFromWorkspace('npm-package');
    const proxyPort = 3128;
    kerberosServer = await startKerberosEnvironment(project, proxyPort);

    const port = process.env.PORT || process.env.SNYK_PORT || '12345';
    const baseApi = '/api/v1';
    env = {
      ...process.env,
      SNYK_API: 'http://localhost:' + port + baseApi,
      SNYK_TOKEN: '123456789',
      HTTP_PROXY: `http://kerberos.snyk.local:3128`,
    };
    server = fakeServer(baseApi, env.SNYK_TOKEN);
    await server.listenPromise(port);
  });

  afterEach(() => {
    server.restore();
  });

  afterAll(async () => {
    await server.closePromise();
    await stopKerberosEnvironment();
    await expect(kerberosServer).toExitWith(0);
  });

  it('fails to connect', async () => {
    // How to get project fixtures into docker container?
    // - Allow function to take output path instead of tmp dir.
    // - Basically, nested workspaces.
    const cli = await startCommand('docker', [
      'exec',
      '-e',
      `SNYK_API=${env.SNYK_API}`,
      '-e',
      `SNYK_TOKEN=${env.SNYK_TOKEN}`,
      '-e',
      `HTTP_PROXY=${env.HTTP_PROXY}`,
      '-w',
      '/etc/cliv2/project',
      'kerberos_cliv2_kerberos_1',
      '/etc/cliv2/bin/snyk',
      'test',
      '-d',
    ]);
    await expect(cli).toExitWith(2);
  });
});
