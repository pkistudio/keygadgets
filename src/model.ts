export type KeyArtifactKind = 'private-key' | 'public-key' | 'certificate' | 'subject-dn' | 'csr';

export type KeyArtifact = {
  id: string;
  kind: KeyArtifactKind;
  label: string;
  bytes: Uint8Array;
};

export type KeyDocument = {
  id: string;
  label: string;
  privateKeyDer?: Uint8Array;
  publicKeyDer?: Uint8Array;
  certificateDer?: Uint8Array;
  subjectDns: KeyArtifact[];
  csrs: KeyArtifact[];
};
