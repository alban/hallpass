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
import { Badge, Box, Button, ButtonGroup, IconButton, Tooltip, Typography } from '@mui/material';
import { useSnackbar } from 'notistack';
import { useState, useSyncExternalStore } from 'react';
import { getStore, Hallpass, useHallpass } from './hooks';
import { policyAnnotation } from './sandbox';
import { pendingCount } from './store';
import {
  AgentState,
  Answer,
  answerAllowed,
  answers,
  PendingRequest,
  ruleObject,
  Session,
  sessionName,
} from './types';

const answerHelp: Record<Answer, string> = {
  once: 'Allow this request only',
  temp: 'Allow the scope until the session ends',
  always: 'Allow the scope, and remember it in the session',
  deny: 'Deny this request only',
  never: 'Deny, and remember it in the session',
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
      {answers.map(a => (
        <Tooltip key={a} title={answerHelp[a]}>
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
    { label: 'Operation', getter: (r: PendingRow) => r.request.prompt?.op || r.request.syscall },
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

function RulesTable(props: { session: Session }) {
  return (
    <SimpleTable
      columns={[
        { label: 'Verdict', getter: r => (r.verdict || 'ALLOW').toLowerCase() },
        { label: 'Object', getter: r => ruleObject(r) },
        { label: 'Label', getter: r => r.label },
        { label: 'Expires', getter: r => r.expires || 'with the session' },
      ]}
      data={props.session.rules || []}
      emptyMessage="No rule."
    />
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
          {sessions.map(({ session }) => (
            <Box key={session.info.id}>
              <Typography variant="h6">Rules of {session.info.labels?.container}</Typography>
              <RulesTable session={session} />
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
