// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

import { ApiProxy } from '@kinvolk/headlamp-plugin/lib';
import { ActionButton } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Typography,
} from '@mui/material';
import { useSnackbar } from 'notistack';
import { useEffect, useState } from 'react';
import { findOwner, Owner, policiesPath, templatePatch } from './sandbox';

const namespaceLabel = 'hallpass.io/enabled';

function SandboxDialog(props: { pod: any; onClose: () => void }) {
  const { pod, onClose } = props;
  const [owner, setOwner] = useState<Owner | null>(null);
  const [policies, setPolicies] = useState<string[]>([]);
  const [policy, setPolicy] = useState('');
  const [nsSelected, setNsSelected] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const { enqueueSnackbar } = useSnackbar();
  const get = (path: string) => ApiProxy.request(path);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [o, list, ns] = await Promise.all([
          findOwner(pod.jsonData, get),
          get(policiesPath),
          get(`/api/v1/namespaces/${pod.metadata.namespace}`).catch(() => null),
        ]);
        if (cancelled) {
          return;
        }
        setOwner(o);
        setPolicy(o.policy);
        setPolicies((list.items || []).map((p: any) => p.metadata.name).sort());
        if (ns) {
          setNsSelected(ns.metadata?.labels?.[namespaceLabel] === 'true');
        }
      } catch (e) {
        if (!cancelled) {
          setError(String(e));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [pod]);

  const apply = async (p: string) => {
    if (!owner) {
      return;
    }
    setBusy(true);
    try {
      await ApiProxy.patch(owner.path, templatePatch(owner.kind, p));
      enqueueSnackbar(
        p
          ? `${owner.kind} ${owner.name} now uses the hallpass policy ${p}`
          : `${owner.kind} ${owner.name} no longer uses hallpass`,
        { variant: 'success' }
      );
      onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Sandbox with hallpass</DialogTitle>
      <DialogContent>
        {error && <Alert severity="error">{error}</Alert>}
        {!owner && !error && <Typography>Looking up the pod's owner…</Typography>}
        {owner?.unsupported && <Alert severity="info">{owner.unsupported}</Alert>}
        {owner && !owner.unsupported && (
          <>
            <Typography sx={{ mb: 2 }}>
              Sets the <code>hallpass.io/policy</code> annotation on the pod template of{' '}
              {owner.kind} <b>{owner.name}</b>. Its pods are recreated: their containers are
              mediated from their start.
            </Typography>
            {!nsSelected && (
              <Alert severity="warning" sx={{ mb: 2 }}>
                The namespace {owner.namespace} does not have the label{' '}
                <code>{namespaceLabel}=true</code>: with the default namespace selector, the
                agent ignores the annotation.
              </Alert>
            )}
            {policies.length === 0 ? (
              <Alert severity="warning">No HallpassPolicy in the cluster.</Alert>
            ) : (
              <FormControl fullWidth>
                <InputLabel id="hallpass-policy">Policy</InputLabel>
                <Select
                  labelId="hallpass-policy"
                  label="Policy"
                  value={policy}
                  onChange={e => setPolicy(String(e.target.value))}
                >
                  {policies.map(p => (
                    <MenuItem key={p} value={p}>
                      {p}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            )}
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        {owner?.policy && !owner.unsupported && (
          <Button color="error" disabled={busy} onClick={() => apply('')}>
            Remove
          </Button>
        )}
        <Button
          variant="contained"
          disabled={busy || !owner || !!owner.unsupported || !policy || policy === owner.policy}
          onClick={() => apply(policy)}
        >
          Apply
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function SandboxAction(props: { item: any }) {
  const [open, setOpen] = useState(false);
  if (props.item?.kind !== 'Pod') {
    return null;
  }
  return (
    <>
      <ActionButton
        description="Sandbox with hallpass"
        icon="mdi:shield-lock-outline"
        onClick={() => setOpen(true)}
      />
      {open && <SandboxDialog pod={props.item} onClose={() => setOpen(false)} />}
    </>
  );
}
