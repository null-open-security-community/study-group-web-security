import React from 'react';
import clsx from 'clsx';
import styles from './HomepageFeatures.module.css';

const FeatureList = [
  {
    title: 'Study Group',
    Svg: require('../../static/img/undraw_community_re_cyrm.svg').default,
    description: (
      <>
        Outcome of the Web Security Study Group by null - The Open Security Community. Contains OWASP Top 10 categorized vulnerabilities, but not just limited to that.
      </>
    ),
  },
  {
    title: 'Learning Resources',
    Svg: require('../../static/img/undraw_data_extraction_re_0rd3.svg').default,
    description: (
      <>
        This place contains plethora of Resources collated to learn web security by the hackers. Be it - Blogs, Practice Labs, Write-ups, etc.
      </>
    ),
  },
  {
    title: 'A Lot More',
    Svg: require('../../static/img/undraw_load_more_re_482p.svg').default,
    description: (
      <>
        Dive in to explore what you can find beneficial and add/contribute to what you find missing. Let's Learn Together!!
      </>
    ),
  },
];

function Feature({Svg, title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} alt={title} />
      </div>
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
