import { NbMenuItem } from '@nebular/theme';

export const MENU_ITEMS: NbMenuItem[] = [
    {
      title: 'Home',
      icon: 'layout-outline',
      link: '/home',
      home: true,
    },
    {
      title: 'Fleet Management',
      icon: 'cube-outline',
      link: '/pages/fleets',
      children: [
        {
          title: 'List View',
        },
        {
          title: 'Metric View',
        },
      ],
    },
    {
      title: 'Dataset Explorer',
      icon: 'layers-outline',
      link: '/pages/datasets',
    },
    {
      title: 'Settings',
      icon: 'settings-2-outline',
      expanded: false,
      children: [
        {
          title: 'Sink Management',
          link: '/pages/sinks',
        },
        {
          title: 'Agent Groups',
          link: '/pages/agents',
        },
        {
          title: 'Policy Management',
          link: '/pages/policies',
        },
      ],
    },
  ];

