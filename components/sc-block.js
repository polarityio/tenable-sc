polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  numIpsShown: 0,
  numNamesShown: 0,
  init () {
    this.set(
      'numIpsShown',
      Math.min(this.get('details.response.returnedRecords'), this.get('details.response.totalRecords'))
    );
    this.set(
      'numNamesShown',
      Math.min(this.get('details.response.returnedRecords'), this.get('details.response.totalRecords'))
    );

    this._super(...arguments);
  },
  actions: {
    toggle: function (prop) {
      this.toggleProperty(prop);
      this.get('block').notifyPropertyChange('data');
    },
    retryLookup: function () {
      this.set('running', true);
      this.set('errorMessage', '');
      const payload = {
        action: 'retryLookup',
        entity: this.get('block.entity')
      };
      this.sendIntegrationMessage(payload)
        .then((result) => {
          if (result.data.summary) this.set('summary', result.summary);
          this.set('block.data', result.data);
        })
        .catch((err) => {
          this.set('details.errorMessage', JSON.stringify(err, null, 4));
        })
        .finally(() => {
          this.set('running', false);
        });
    }
  }
});
