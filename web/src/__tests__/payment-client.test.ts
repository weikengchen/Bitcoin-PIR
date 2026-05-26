import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  getArcPubkey,
  issueArcCredential,
  getCashuKeyset,
  mintCashuBats,
  presentArc,
  presentCashu,
  ARC_PUBKEY_BYTES,
  ARC_REQUEST_BYTES,
  ARC_RESPONSE_BYTES,
  CASHU_POINT_BYTES,
} from '../payment-client.js';

function okResponse(bytes: Uint8Array): Response {
  return new Response(bytes as BodyInit, { status: 200 });
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('getArcPubkey', () => {
  it('returns the 99-byte pubkey and hits the right URL', async () => {
    const pubkey = new Uint8Array(ARC_PUBKEY_BYTES).fill(7);
    const fetchMock = vi.fn(async () => okResponse(pubkey));
    vi.stubGlobal('fetch', fetchMock);

    const out = await getArcPubkey('http://localhost:5601');
    expect(out.length).toBe(ARC_PUBKEY_BYTES);
    expect(out[0]).toBe(7);
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:5601/dev/arc/pubkey',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('normalizes a trailing slash in the base URL', async () => {
    const fetchMock = vi.fn(async () => okResponse(new Uint8Array(ARC_PUBKEY_BYTES)));
    vi.stubGlobal('fetch', fetchMock);
    await getArcPubkey('http://localhost:5601/');
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:5601/dev/arc/pubkey',
      expect.anything(),
    );
  });

  it('throws on a wrong-length pubkey', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => okResponse(new Uint8Array(98))));
    await expect(getArcPubkey('http://x')).rejects.toThrow(/expected 99 bytes, got 98/);
  });

  it('throws on an HTTP error status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 500 })));
    await expect(getArcPubkey('http://x')).rejects.toThrow(/HTTP 500/);
  });

  it('throws a clear error when the issuer is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('ECONNREFUSED'); }));
    await expect(getArcPubkey('http://x')).rejects.toThrow(/unreachable/);
  });
});

describe('issueArcCredential', () => {
  it('rejects a wrong-length request before fetching', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(
      issueArcCredential('http://x', new Uint8Array(10)),
    ).rejects.toThrow(/expected 226 bytes, got 10/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('posts the request and returns the 454-byte response', async () => {
    const response = new Uint8Array(ARC_RESPONSE_BYTES).fill(3);
    const fetchMock = vi.fn(async () => okResponse(response));
    vi.stubGlobal('fetch', fetchMock);

    const out = await issueArcCredential(
      'http://localhost:5601',
      new Uint8Array(ARC_REQUEST_BYTES).fill(9),
    );
    expect(out.length).toBe(ARC_RESPONSE_BYTES);
    expect(out[0]).toBe(3);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://localhost:5601/dev/arc/issue');
    expect(init.method).toBe('POST');
  });

  it('surfaces the issuer error body on HTTP 400', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('invalid CredentialRequest', { status: 400 })),
    );
    await expect(
      issueArcCredential('http://x', new Uint8Array(ARC_REQUEST_BYTES)),
    ).rejects.toThrow(/HTTP 400 — invalid CredentialRequest/);
  });

  it('throws on a wrong-length response', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => okResponse(new Uint8Array(100))));
    await expect(
      issueArcCredential('http://x', new Uint8Array(ARC_REQUEST_BYTES)),
    ).rejects.toThrow(/expected 454 bytes, got 100/);
  });
});

function jsonResponse(obj: unknown): Response {
  return new Response(JSON.stringify(obj), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

const PUBKEY_HEX = '02' + 'ab'.repeat(32); // 66 hex chars → 33 bytes

describe('getCashuKeyset', () => {
  it('returns {id, pubkey(33)} and hits the right URL', async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ id: '02abcd-auth', pubkey: PUBKEY_HEX }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const keyset = await getCashuKeyset('http://localhost:5601/');
    expect(keyset.id).toBe('02abcd-auth');
    expect(keyset.pubkey.length).toBe(CASHU_POINT_BYTES);
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:5601/dev/cashu/keyset',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('throws on a non-33-byte pubkey', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ id: 'x', pubkey: '02ab' })));
    await expect(getCashuKeyset('http://x')).rejects.toThrow(/expected 33 bytes/);
  });

  it('throws on missing fields', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ id: 'x' })));
    await expect(getCashuKeyset('http://x')).rejects.toThrow(/missing string id\/pubkey/);
  });

  it('throws on an HTTP error status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 503 })));
    await expect(getCashuKeyset('http://x')).rejects.toThrow(/HTTP 503/);
  });
});

describe('mintCashuBats', () => {
  it('rejects a non-multiple-of-33 batch before fetching', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(mintCashuBats('http://x', new Uint8Array(40))).rejects.toThrow(
      /non-empty multiple of 33 bytes, got 40/,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects an empty batch', async () => {
    vi.stubGlobal('fetch', vi.fn());
    await expect(mintCashuBats('http://x', new Uint8Array(0))).rejects.toThrow(
      /non-empty multiple of 33/,
    );
  });

  it('posts N×33 and returns N×33 signatures', async () => {
    const sigs = new Uint8Array(2 * CASHU_POINT_BYTES).fill(5);
    const fetchMock = vi.fn(async () => okResponse(sigs));
    vi.stubGlobal('fetch', fetchMock);

    const out = await mintCashuBats(
      'http://localhost:5601',
      new Uint8Array(2 * CASHU_POINT_BYTES).fill(2),
    );
    expect(out.length).toBe(2 * CASHU_POINT_BYTES);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://localhost:5601/dev/cashu/mint');
    expect(init.method).toBe('POST');
  });

  it('throws when the response count does not match the request', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => okResponse(new Uint8Array(CASHU_POINT_BYTES))));
    await expect(
      mintCashuBats('http://x', new Uint8Array(2 * CASHU_POINT_BYTES)),
    ).rejects.toThrow(/expected 66 bytes back/);
  });

  it('surfaces the mint error body on HTTP 400', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('invalid blinded point encoding', { status: 400 })),
    );
    await expect(
      mintCashuBats('http://x', new Uint8Array(CASHU_POINT_BYTES)),
    ).rejects.toThrow(/HTTP 400 — invalid blinded point encoding/);
  });
});

describe('presentArc / presentCashu', () => {
  // A fake present frame: [4B len][payload]. The helper strips the 4B prefix.
  const frame = new Uint8Array([99, 0, 0, 0, 0x08, 0xaa, 0xbb, 0xcc]);

  it('presentArc returns {ok:true} on 200 and strips the length prefix', async () => {
    const fetchMock = vi.fn(async () => new Response('ok\n', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await presentArc('http://localhost:5601', frame);
    expect(result.ok).toBe(true);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://localhost:5601/dev/arc/verify');
    // Body is the frame minus the 4-byte length prefix → [0x08,0xaa,0xbb,0xcc].
    expect((init.body as Uint8Array).length).toBe(frame.length - 4);
    expect((init.body as Uint8Array)[0]).toBe(0x08);
  });

  it('presentArc returns {ok:false, reason} on 400', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('duplicate ARC tag — nonce reused', { status: 400 })),
    );
    const result = await presentArc('http://x', frame);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/duplicate ARC tag/);
  });

  it('presentCashu hits the cashu verify endpoint', async () => {
    const fetchMock = vi.fn(async () => new Response('ok\n', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const cashuFrame = new Uint8Array([5, 0, 0, 0, 0x09, 0x61, 0x75, 0x74, 0x68]);
    const result = await presentCashu('http://x', cashuFrame);
    expect(result.ok).toBe(true);
    const [url] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://x/dev/cashu/verify');
  });

  it('presentCashu reports double-spend rejection', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('BAT already spent', { status: 400 })));
    const result = await presentCashu('http://x', new Uint8Array([1, 0, 0, 0, 0x09]));
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/already spent/);
  });
});
