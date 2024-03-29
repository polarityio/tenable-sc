module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'tenable.sc (Security Center)',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'SC',
  defaultColor: 'dark-orange',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    'Search Tenable.sc scan results by IP address or by CVE.',
  entityTypes: ['IPv4', 'cve'],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/sc.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './components/sc-block.js'
    },
    template: {
      file: './templates/sc-block.hbs'
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: ""
  },
  logging: {
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'url',
      name: 'tenable.sc URL',
      description: 'The base URL for the tenable.sc server including the schema (i.e., https://). This option must be set to "Users can view only".',
      type: 'text',
      default: '',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'userName',
      name: 'tenable.sc Username',
      description: 'Valid tenable.sc Username',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'password',
      name: 'tenable.sc Password',
      description: 'Valid tenable.sc Password',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'maxResults',
      name: 'Maximum Number of CVE Search Results to Return',
      description: 'Maximum number of CVE search results to return',
      default: 50,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'maxConcurrent',
      name: 'Max Concurrent Requests',
      description:
        'Maximum number of concurrent requests.  Integration must be restarted after changing this option. Defaults to 20.',
      default: 20,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'minTime',
      name: 'Minimum Time Between Lookups',
      description:
        'Minimum amount of time in milliseconds between lookups. Integration must be restarted after changing this option. Defaults to 100.',
      default: 100,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    }
  ]
};