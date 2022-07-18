import * as path from 'path';
import { fakeServer, FakeServer } from '../../../test/acceptance/fake-server';
import {
  createProjectFromWorkspace,
  TestProject,
} from '../../../test/jest/util/createProject';
import { startCommand } from '../../../test/jest/util/startSnykCLI';

jest.setTimeout(1000 * 60);

// Global test configuration
const dockerComposeFile = path.resolve(
  'test/fixtures/kerberos/docker-compose.yml',
);
const containerName = 'kerberos_cliv2_kerberos_1';
const hostnameFakeServer = 'host.docker.internal';
const hostnameProxy = 'kerberos.snyk.local';
const proxyPort = '3128';
const port = process.env.PORT || process.env.SNYK_PORT || '12345';
const baseApi = '/api/v1';
const SNYK_API = 'http://' + hostnameFakeServer + ':' + port + baseApi;
const HTTP_PROXY = 'http://' + hostnameProxy + ':' + proxyPort;

function getDockerOptions(projectPath = '') {
  const dockerOptions = {
    env: {
      ...process.env,
      HTTP_PROXY_PORT: proxyPort,
      PROJECT_PATH: projectPath,
      PROXY_HOSTNAME: hostnameProxy,
      SNYK_API: SNYK_API,
    },
  };
  return dockerOptions;
}

function getDockerExecSnykCommand(env: Record<string, string>, cmd = 'test') {
  const command = [
    'exec',
    '-e',
    'SNYK_HTTP_PROTOCOL_UPGRADE=0',
    '-e',
    `SNYK_API=${env.SNYK_API}`,
    '-e',
    `SNYK_TOKEN=${env.SNYK_TOKEN}`,
    '-e',
    `HTTP_PROXY=${env.HTTP_PROXY}`,
    '-e',
    `HTTPS_PROXY=${env.HTTP_PROXY}`,
    '-w',
    '/etc/cliv2/project',
    containerName,
    '/etc/cliv2/bin/snyk',
    cmd,
    '--debug',
  ];
  return command;
}

async function startKerberosEnvironment(project: TestProject): Promise<void> {
  // Stop any orphaned containers from previous runs.
  await stopKerberosEnvironment();

  const dockerUp = await startCommand(
    'docker-compose',
    ['--file', dockerComposeFile, 'up', '--build'],
    getDockerOptions(project.path()),
  );
  await expect(dockerUp).toDisplay('Kerberos setup complete.', {
    timeout: 30_000,
  });
}

async function stopKerberosEnvironment(): Promise<void> {
  const dockerDown = await startCommand(
    'docker-compose',
    ['--file', dockerComposeFile, 'down'],
    getDockerOptions(),
  );
  await expect(dockerDown).toExitWith(0, { timeout: 30_000 });
}

async function getAccessLog(): Promise<string> {
  const check = await startCommand('docker', [
    'exec',
    containerName,
    'cat',
    '/var/log/squid/access.log',
  ]);
  await expect(check).toExitWith(0);
  return check.stdout.get();
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

  beforeAll(async () => {
    project = await createProjectFromWorkspace('npm-package');
    await startKerberosEnvironment(project);

    env = {
      ...process.env,
      SNYK_API: SNYK_API,
      SNYK_TOKEN: '123456789',
      HTTP_PROXY: HTTP_PROXY,
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
  });

  it('fails to run snyk test due to missing --proxy-negotiate', async () => {
    // How to get project fixtures into docker container?
    // - Allow function to take output path instead of tmp dir.
    // - Basically, nested workspaces.
    const logOnEntry = await getAccessLog();

    // run snyk test
    const cli = await startCommand('docker', getDockerExecSnykCommand(env));
    await expect(cli).toExitWith(2);

    const logOnExit = await getAccessLog();
    const additionalLogEntries = logOnExit.substring(logOnEntry.length);
    expect(additionalLogEntries.includes('TCP_DENIED/407')).toBeTruthy();
    expect(
      additionalLogEntries.includes(
        'CONNECT ' + hostnameFakeServer + ':' + port,
      ),
    ).toBeFalsy();
  });

  it('successfully runs snyk test', async () => {
    const logOnEntry = await getAccessLog();

    // run snyk test
    const cmd = getDockerExecSnykCommand(env);
    cmd.push('--proxy-negotiate');
    const cli = await startCommand('docker', cmd);
    await expect(cli).toExitWith(0);

    const logOnExit = await getAccessLog();
    const additionalLogEntries = logOnExit.substring(logOnEntry.length);
    expect(additionalLogEntries.includes('TCP_TUNNEL/200')).toBeTruthy();
    expect(
      additionalLogEntries.includes(
        'CONNECT ' + hostnameFakeServer + ':' + port,
      ),
    ).toBeTruthy();
  });
});
