// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// The hallpass Headlamp plugin: answers the requests of the containers
// that hallpass mediates, through the node agents' session API. See
// docs/kubernetes.md.

import {
  registerAppBarAction,
  registerDetailsViewSection,
  registerResourceTableColumnsProcessor,
  registerRoute,
  registerSidebarEntry,
} from '@kinvolk/headlamp-plugin/lib';
import { HallpassView, PendingBadge, PodColumn, PodSection, podStatusNow } from './components';

registerSidebarEntry({
  parent: null,
  name: 'hallpass',
  label: 'hallpass',
  url: '/hallpass',
  icon: 'mdi:shield-lock-outline',
});

registerRoute({
  path: '/hallpass',
  sidebar: 'hallpass',
  name: 'hallpass',
  exact: true,
  component: () => <HallpassView />,
});

registerAppBarAction(<PendingBadge />);

registerDetailsViewSection(({ resource }) => {
  if (resource?.kind !== 'Pod') {
    return null;
  }
  return <PodSection resource={resource as any} />;
});

registerResourceTableColumnsProcessor(function hallpassColumn({ id, columns }) {
  if (id === 'headlamp-pods') {
    columns.push({
      id: 'hallpass',
      label: 'hallpass',
      getValue: (pod: any) => podStatusNow(pod),
      render: (pod: any) => <PodColumn pod={pod} />,
    });
  }
  return columns;
});
