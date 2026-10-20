// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

import { Icon } from '@iconify/react';
import {
  Link,
  NameValueTable,
  SectionBox,
  SimpleTable,
  StatusLabel,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import type Pod from '@kinvolk/headlamp-plugin/lib/lib/k8s/pod';
import { getCluster, localeDate } from '@kinvolk/headlamp-plugin/lib/Utils';
import {
  Badge,
  Box,
  Button,
  ButtonGroup,
  IconButton,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import { useSnackbar } from 'notistack';
import { useState, useSyncExternalStore } from 'react';
import { getStore, Hallpass, useHallpass } from './hooks';
import { policyAnnotation } from './sandbox';
import { pendingCount, RulesChange } from './store';
import {
  AgentState,
  Answer,
  answerAllowed,
  answersFor,
  editLabel,
  forSuffix,
  grantForText,
  PendingRequest,
  Rule,
  ruleObject,
  ruleSyntax,
  Session,
  sessionName,
} from './types';

const answerHelp: Record<Answer, string> = {
  once: 'Allow this request only',
  temp: 'Allow the scope until the session ends',
  always: 'Allow the scope, and remember it in the session',
  group: 'Allow every program of the group, and remember it in the session',
  deny: 'Deny this request only',
  never: 'Deny, and remember it in the session',
  grant: 'Grant what the program asks for in advance, for the time it asks',
};

function AnswerButtons(props: {
  hp: Hallpass;
  agent: AgentState;
  session: Session;
  request: PendingRequest;
}) {
  const { hp, agent, session, request } = props;
  const [busy, setBusy] = useState(false);
  const { enqueueSnackbar } = useSnackbar();
  const answer = async (a: Answer) => {
    setBusy(true);
    try {
      await hp.answer(agent.pod, session.info.id || '', request.id, a);
    } catch (e) {
      enqueueSnackbar(`hallpass: ${a} ${request.prompt?.path || request.id}: ${e}`, {
        variant: 'error',
      });
    } finally {
      setBusy(false);
    }
  };
  return (
    <ButtonGroup size="small" variant="outlined" disabled={busy}>
      {answersFor(request.prompt)
        // Only execs have a group: no disabled button on every other prompt.
        .filter(a => a !== 'group' || answerAllowed(a, request.prompt))
        .map(a => (
          <Tooltip key={a} title={a === 'group' ? `Allow ${request.prompt?.group}` : answerHelp[a]}>
            <span>
              <Button
                color={a === 'deny' || a === 'never' ? 'error' : 'primary'}
                disabled={busy || !answerAllowed(a, request.prompt)}
                onClick={() => answer(a)}
                aria-label={`${a} ${request.prompt?.path || ''}`}
              >
                {a}
              </Button>
            </span>
          </Tooltip>
        ))}
    </ButtonGroup>
  );
}

interface PendingRow {
  agent: AgentState;
  session: Session;
  request: PendingRequest;
}

function pendingRows(agents: AgentState[], filter?: (s: Session) => boolean): PendingRow[] {
  const rows: PendingRow[] = [];
  for (const agent of agents) {
    for (const session of agent.sessions) {
      if (filter && !filter(session)) {
        continue;
      }
      for (const request of session.pending || []) {
        rows.push({ agent, session, request });
      }
    }
  }
  return rows;
}

function Process(props: { request: PendingRequest }) {
  const p = props.request.prompt || {};
  const chain = [p.exe || '', ...(p.parents || [])].filter(x => x).join(' ← ');
  return (
    <Tooltip title={(p.cmdline || []).join(' ')}>
      <span>
        {chain} {p.pid ? `(${p.pid})` : ''}
      </span>
    </Tooltip>
  );
}

function PendingTable(props: {
  hp: Hallpass;
  filter?: (s: Session) => boolean;
  showSession?: boolean;
}) {
  const { hp, filter, showSession = true } = props;
  const rows = pendingRows(hp.agents, filter);
  const columns = [
    ...(showSession
      ? [
          {
            label: 'Container',
            getter: (r: PendingRow) => <SessionLink session={r.session} />,
          },
        ]
      : []),
    {
      label: 'Operation',
      getter: (r: PendingRow) =>
        r.request.prompt?.advance
          ? `${r.request.prompt.op || 'write'}, asked in advance ${grantForText(
              r.request.prompt.grantFor
            )}`
          : r.request.prompt?.op || r.request.syscall,
    },
    {
      label: 'Path',
      getter: (r: PendingRow) => (
        <>
          {r.request.prompt?.path}
          {r.request.prompt?.detail && ` · ${r.request.prompt.detail}`}
          {r.request.prompt?.warn && (
            <>
              {' '}
              <StatusLabel status="warning">{r.request.prompt.warn}</StatusLabel>
            </>
          )}
          {r.request.prompt?.note && ` (${r.request.prompt.note})`}
          {r.request.prompt?.reason && (
            <Typography variant="body2" color="text.secondary">
              reason given by the program (unverified): <q>{r.request.prompt.reason}</q>
            </Typography>
          )}
        </>
      ),
    },
    { label: 'Process', getter: (r: PendingRow) => <Process request={r.request} /> },
    {
      label: 'Answer',
      getter: (r: PendingRow) => (
        <AnswerButtons hp={hp} agent={r.agent} session={r.session} request={r.request} />
      ),
    },
  ];
  return <SimpleTable columns={columns} data={rows} emptyMessage="No pending requests." />;
}

function SessionLink(props: { session: Session }) {
  const l = props.session.info.labels || {};
  if (!l.namespace || !l.pod) {
    return <>{sessionName(props.session)}</>;
  }
  return (
    <>
      <Link routeName="pod" params={{ namespace: l.namespace, name: l.pod }}>
        {l.namespace}/{l.pod}
      </Link>
      /{l.container}
    </>
  );
}

function AgentStatus(props: { agent: AgentState }) {
  const a = props.agent;
  if (a.connected) {
    return <StatusLabel status="success">connected</StatusLabel>;
  }
  return (
    <Tooltip title={a.error || ''}>
      <span>
        <StatusLabel status={a.error ? 'error' : ''}>
          {a.error ? 'disconnected' : 'connecting'}
        </StatusLabel>
      </span>
    </Tooltip>
  );
}

function ListError(props: { hp: Hallpass }) {
  const { hp } = props;
  if (hp.listError) {
    return <Typography color="error">Listing the hallpass-node pods: {hp.listError}</Typography>;
  }
  if (hp.listed && hp.agents.length === 0) {
    return (
      <Typography>
        No running hallpass-node pod in the hallpass-system namespace: is hallpass installed?
      </Typography>
    );
  }
  return null;
}

function started(s: Session): string {
  return s.info.startTime ? localeDate(s.info.startTime) : '';
}

export function HallpassView() {
  const hp = useHallpass();
  const sessions = hp.agents.flatMap(agent => agent.sessions.map(session => ({ agent, session })));
  return (
    <>
      <SectionBox title="Pending requests">
        <ListError hp={hp} />
        <PendingTable hp={hp} />
      </SectionBox>
      <SectionBox title="Sessions">
        <SimpleTable
          columns={[
            { label: 'Container', getter: r => <SessionLink session={r.session} /> },
            { label: 'Node', getter: r => r.agent.node },
            { label: 'Policy', getter: r => r.session.info.labels?.policy },
            { label: 'Pending', getter: r => r.session.pending?.length || 0 },
            { label: 'Rules', getter: r => r.session.rules?.length || 0 },
            { label: 'Started', getter: r => started(r.session) },
          ]}
          data={sessions}
          emptyMessage="No mediated container."
        />
      </SectionBox>
      <SectionBox title="Agents">
        <SimpleTable
          columns={[
            { label: 'Node', getter: (a: AgentState) => a.node },
            { label: 'Pod', getter: (a: AgentState) => a.pod },
            { label: 'Status', getter: (a: AgentState) => <AgentStatus agent={a} /> },
            { label: 'Sessions', getter: (a: AgentState) => a.sessions.length },
          ]}
          data={hp.agents}
          emptyMessage="No agent."
        />
      </SectionBox>
    </>
  );
}

function ClusterBadge() {
  const hp = useHallpass();
  const n = pendingCount(hp.agents);
  return (
    <Tooltip title={`hallpass: ${n} pending request${n === 1 ? '' : 's'}`}>
      <span>
        <Link routeName="hallpass">
          <IconButton aria-label="hallpass pending requests" size="medium">
            <Badge badgeContent={n} color="error" data-testid="hallpass-badge">
              <Icon icon="mdi:shield-lock-outline" />
            </Badge>
          </IconButton>
        </Link>
      </span>
    </Tooltip>
  );
}

// The app bar is also shown outside of clusters; the badge also keeps the
// connections to the agents open while Headlamp is on a cluster page.
export function PendingBadge() {
  if (!getCluster()) {
    return null;
  }
  return <ClusterBadge />;
}

// RulesTable lists a session's rules, and edits, deletes and adds them.
function RulesTable(props: { hp: Hallpass; agent: AgentState; session: Session }) {
  const { hp, agent, session } = props;
  const [editing, setEditing] = useState<{ id: string; text: string; generation: string } | null>(
    null
  );
  const [adding, setAdding] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { enqueueSnackbar } = useSnackbar();
  const change = async (what: string, c: RulesChange): Promise<boolean> => {
    setBusy(true);
    try {
      await hp.rules(agent.pod, session.info.id || '', c);
      return true;
    } catch (e) {
      enqueueSnackbar(`hallpass: ${what}: ${e}`, { variant: 'error' });
      return false;
    } finally {
      setBusy(false);
    }
  };
  const save = async (r: Rule) => {
    if (!editing) {
      return;
    }
    const ok = await change(`edit rule ${r.id}`, {
      remove: [r.id || ''],
      add: [editing.text],
      label: editLabel(r),
      generation: editing.generation,
    });
    if (ok) {
      setEditing(null);
    } else {
      // Saving again applies to the rules shown now.
      setEditing({ ...editing, generation: session.generation || '' });
    }
  };
  const add = async () => {
    if (adding !== null && (await change('add rule', { add: [adding] }))) {
      setAdding(null);
    }
  };
  const specField = (
    value: string,
    set: (v: string) => void,
    submit: () => void,
    label: string
  ) => (
    <TextField
      size="small"
      fullWidth
      value={value}
      disabled={busy}
      placeholder="allow path /data/** for 1h"
      inputProps={{ 'aria-label': label, spellCheck: false, style: { fontFamily: 'monospace' } }}
      onChange={e => set(e.target.value)}
      onKeyDown={e => {
        if (e.key === 'Enter') {
          submit();
        }
      }}
    />
  );
  return (
    <>
      <SimpleTable
        columns={[
          {
            label: 'Rule',
            getter: (r: Rule) =>
              editing && editing.id === r.id ? (
                specField(
                  editing.text,
                  text => setEditing({ ...editing, text }),
                  () => save(r),
                  `rule ${r.id}`
                )
              ) : (
                <>
                  {(r.verdict || 'ALLOW').toLowerCase()} {ruleObject(r)}
                </>
              ),
          },
          { label: 'Label', getter: (r: Rule) => r.label },
          { label: 'Expires', getter: (r: Rule) => r.expires || 'with the session' },
          {
            label: '',
            getter: (r: Rule) =>
              editing && editing.id === r.id ? (
                <ButtonGroup size="small" variant="outlined" disabled={busy}>
                  <Button onClick={() => save(r)}>Save</Button>
                  <Button onClick={() => setEditing(null)}>Cancel</Button>
                </ButtonGroup>
              ) : (
                <ButtonGroup size="small" variant="outlined" disabled={busy}>
                  <Button
                    aria-label={`edit rule ${r.id}`}
                    onClick={() =>
                      setEditing({
                        id: r.id || '',
                        text: (r.spec || '') + forSuffix(r.expires, Date.now()),
                        generation: session.generation || '',
                      })
                    }
                  >
                    Edit
                  </Button>
                  <Button
                    color="error"
                    aria-label={`delete rule ${r.id}`}
                    onClick={() => change(`delete rule ${r.id}`, { remove: [r.id || ''] })}
                  >
                    Delete
                  </Button>
                </ButtonGroup>
              ),
          },
        ]}
        data={session.rules || []}
        emptyMessage="No rule."
      />
      {adding === null ? (
        <Button size="small" onClick={() => setAdding('')}>
          Add rule
        </Button>
      ) : (
        <Box display="flex" gap={1} alignItems="center" mt={1}>
          {specField(adding, setAdding, add, 'new rule')}
          <ButtonGroup size="small" variant="outlined" disabled={busy}>
            <Button onClick={add}>Add</Button>
            <Button onClick={() => setAdding(null)}>Cancel</Button>
          </ButtonGroup>
        </Box>
      )}
      {(adding !== null || editing) && (
        <Typography variant="body2" color="text.secondary" mt={1}>
          {ruleSyntax}
        </Typography>
      )}
    </>
  );
}

function podSessions(agents: AgentState[], pod: Pod) {
  const uid = pod.metadata.uid;
  const match = (s: Session) =>
    s.info.labels?.podUID === uid ||
    (s.info.labels?.namespace === pod.metadata.namespace &&
      s.info.labels?.pod === pod.metadata.name);
  const sessions: { agent: AgentState; session: Session }[] = [];
  for (const agent of agents) {
    for (const session of agent.sessions) {
      if (match(session)) {
        sessions.push({ agent, session });
      }
    }
  }
  return { match, sessions };
}

export function PodSection(props: { resource: Pod }) {
  const pod = props.resource;
  const hp = useHallpass();
  const policy = pod.metadata.annotations?.[policyAnnotation];
  const { match, sessions } = podSessions(hp.agents, pod);
  if (!policy && sessions.length === 0) {
    return null;
  }
  return (
    <SectionBox title="hallpass">
      <NameValueTable
        rows={[
          { name: 'Policy', value: policy || '' },
          {
            name: 'Mediated containers',
            value:
              sessions.map(s => s.session.info.labels?.container).join(', ') ||
              'none: no session on the node agent',
          },
        ]}
      />
      <ListError hp={hp} />
      {sessions.length > 0 && (
        <>
          <Typography variant="h6">Pending requests</Typography>
          <PendingTable hp={hp} filter={match} showSession={false} />
          {sessions.map(({ agent, session }) => (
            <Box key={session.info.id}>
              <Typography variant="h6">Rules of {session.info.labels?.container}</Typography>
              <RulesTable hp={hp} agent={agent} session={session} />
            </Box>
          ))}
        </>
      )}
    </SectionBox>
  );
}

// podStatus is the pod list column's value: whether the pod has a session
// and its number of pending requests, from the connections the badge keeps
// open. An annotated pod may have none: its namespace is not selected, or
// it ended.
export function podStatus(pod: Pod, agents: AgentState[]): string {
  const { sessions } = podSessions(agents, pod);
  if (sessions.length === 0) {
    return '';
  }
  const n = sessions.reduce((n, s) => n + (s.session.pending?.length || 0), 0);
  return n > 0 ? `${n} pending` : 'mediated';
}

export function podStatusNow(pod: Pod): string {
  const cluster = (pod as any).cluster || getCluster() || '';
  return podStatus(pod, getStore(cluster).getSnapshot());
}

export function PodColumn(props: { pod: Pod }) {
  const cluster = (props.pod as any).cluster || getCluster() || '';
  const store = getStore(cluster);
  const agents = useSyncExternalStore(store.subscribe, store.getSnapshot);
  const status = podStatus(props.pod, agents);
  if (status.endsWith('pending')) {
    return <StatusLabel status="warning">{status}</StatusLabel>;
  }
  return <>{status}</>;
}
