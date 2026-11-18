# PassMetric demonstration

[MP4 walkthrough](media/walkthrough.mp4) · [Animated preview](media/walkthrough.gif)

Captured from the running application on **17 November 2026**, based on commit
`35577ee`. This is a 24-second sequence of real screenshots with captions, not a
continuous screen recording. Screenshots retain the application's actual UI.

## Journey

1. [Sign in](media/01-login.jpg) to a pre-verified synthetic account.
2. [Add a fictional credential](media/02-add-entry.jpg) through the normal form.
3. [View the saved entry](media/03-vault.jpg) alongside five seeded examples.
4. [Analyse `password123`](media/04-analyser.jpg): the backend returns 19/100,
   identifies a common password and offers specific recommendations.
5. [Generate a password](media/05-generator.jpg) using the selected options.
6. [Audit the vault](media/06-health-audit.jpg): six entries, four weak passwords
   and a mean backend score of 45.4 in this fixture.

All addresses use `example.com`; entries and passwords are fictional. No SMTP
messages were sent. A local seed script created the account as verified, so this
capture does not demonstrate registration or email delivery. CSRF protection,
authentication, encryption and the application's routes remained enabled.

No RockYou corpus, EFF wordlist or trained pickle model was supplied. The existing
NLTK words corpus was available on the capture machine. The screenshots therefore
demonstrate the rules path, not ML accuracy or breach coverage.

## Reproduce the workflow

Follow the README's local setup in an isolated checkout. Create and verify a
test account using your own local configuration; use fictional details. Add some
dummy credentials, open Analyzer and try `password123`, then open Generator and
Health Audit. Never use demonstration passwords for real accounts.

The capture used Python 3.12.14 and the pinned PassMetric requirements. The app ran
on loopback port 8801. The temporary seed/launch scripts and database are excluded
from the publication package; they are not new application features.

## Verification and known discrepancies

The existing unit/integration suites were run in a separate disposable checkout
with an explicit writable pytest temporary directory: **129 passed, 2 failed,
1 skipped**. The skip requires the optional RockYou dataset. The two failures
are `test_strong_password_scores_high` and `test_analyze_strong_password`; both
expect at least 60 for the same fixture, while the evaluator returns 55 here.
No test assertions or evaluator code were changed for this presentation task.

```sh
python -m pytest backend/tests/unit backend/tests/integration -q --basetemp ./pytest-demo-temp
```

Use that command only in the disposable checkout described by the README: the
integration fixture recreates tables. An initial sandbox run had 12 temporary
directory permission errors; those disappeared with an explicit writable path.

The vault displays a lightweight browser score of 50 for `password123`, whereas
the full analyser/audit returns 19. The overview similarly counts one weak
password in this fixture while the backend audit counts four. These are existing
differences between evaluation paths, not evidence of equivalent scoring. Unifying
those paths and resolving the two test expectations is a useful next maintenance
checkpoint.
