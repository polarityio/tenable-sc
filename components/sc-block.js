polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  numIpsShown: 0,
  numNamesShown: 0,
  init() {
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
    }
  }
});
