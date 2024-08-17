import { HyperLink } from '../src';

const testPassword = 'testPassword123';

test('returns valid HyperLink with password (version 0)', async () => {
  const hyperLink = await HyperLink.create(0, testPassword);
  expect(typeof hyperLink.url.hash).toBe('string');
  expect(hyperLink.url.hash.length).toBeGreaterThan(0);
  expect(typeof hyperLink.keypair.publicKey.toBase58()).toBe('string');
  expect(hyperLink.keypair.publicKey.toBase58().length).toBeGreaterThan(0);
});

test('returns valid HyperLink with password (version 1)', async () => {
  const hyperLink = await HyperLink.create(1, testPassword);
  expect(typeof hyperLink.url.hash).toBe('string');
  expect(hyperLink.url.hash.length).toBeGreaterThan(0);
  expect(hyperLink.url.hash.startsWith('#_1_')).toBe(true);
  expect(typeof hyperLink.keypair.publicKey.toBase58()).toBe('string');
  expect(hyperLink.keypair.publicKey.toBase58().length).toBeGreaterThan(0);
});

test('returns valid HyperLink with password (version 2)', async () => {
  const hyperLink = await HyperLink.create(2, testPassword);
  expect(typeof hyperLink.url.hash).toBe('string');
  expect(hyperLink.url.hash.length).toBeGreaterThan(0);
  expect(hyperLink.url.hash.startsWith('#_2_')).toBe(true);
  expect(typeof hyperLink.keypair.publicKey.toBase58()).toBe('string');
  expect(hyperLink.keypair.publicKey.toBase58().length).toBeGreaterThan(0);
});

test('matches website and verifies password (version 0)', async () => {
  const originalHyperLink = await HyperLink.create(0, testPassword);
  const link = originalHyperLink.url.toString();

  const hyperLink = await HyperLink.fromLink(link);
  expect(hyperLink.url.hash).toBe(originalHyperLink.url.hash);
  expect(hyperLink.keypair.publicKey.toBase58()).toBe(
    originalHyperLink.keypair.publicKey.toBase58()
  );
});

test('matches website and verifies password (version 1)', async () => {
  const originalHyperLink = await HyperLink.create(1, testPassword);
  const link = originalHyperLink.url.toString();

  const hyperLink = await HyperLink.fromLink(link);
  expect(hyperLink.url.hash).toBe(originalHyperLink.url.hash);
  expect(hyperLink.keypair.publicKey.toBase58()).toBe(
    originalHyperLink.keypair.publicKey.toBase58()
  );
});

test('matches website and verifies password (version 2)', async () => {
  const originalHyperLink = await HyperLink.create(2, testPassword);
  const link = originalHyperLink.url.toString();

  const hyperLink = await HyperLink.fromLink(link, testPassword);
  expect(hyperLink.url.hash).toBe(originalHyperLink.url.hash);
  expect(hyperLink.keypair.publicKey.toBase58()).toBe(
    originalHyperLink.keypair.publicKey.toBase58()
  );
});

test('denies access with incorrect password (version 2)', async () => {
  const hyperLink = await HyperLink.create(2, testPassword);
  const link = hyperLink.url.toString();

  await expect(HyperLink.fromLink(link, 'wrongPassword')).rejects.toThrow();
});

test('throws error when password is not provided for version 2', async () => {
  const hyperLink = await HyperLink.create(2, testPassword);
  const link = hyperLink.url.toString();

  await expect(HyperLink.fromLink(link)).rejects.toThrow('Password is required for version 2 links');
});

test('creates and retrieves HyperLink with all versions', async () => {
  for (const version of [0, 1, 2]) {
    const hyperLink = await HyperLink.create(version, testPassword);
    const link = hyperLink.url.toString();

    let retrievedHyperLink;
    if (version === 2) {
      retrievedHyperLink = await HyperLink.fromLink(link, testPassword);
    } else {
      retrievedHyperLink = await HyperLink.fromLink(link);
    }

    expect(retrievedHyperLink.url.hash).toBe(hyperLink.url.hash);
    expect(retrievedHyperLink.keypair.publicKey.toBase58()).toBe(
      hyperLink.keypair.publicKey.toBase58()
    );
  }
});