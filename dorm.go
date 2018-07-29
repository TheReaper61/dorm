package dorm

import (
	"fmt"
	"strings"

	uuid "github.com/satori/go.uuid"
)

const historyPrefix = "zoom_"

// ProcessUUID is the uniq id given to the dorm process
var ProcessUUID = ""

func init() {

	// give this process a unique UUID
	ProcessUUID = uuid.NewV4().String()

	// initialize behaviours
	initStaticBehaviors()
	initDynamicBehaviors()
}

func initStaticBehaviors() {

	// UID10
	behave[UID10{}] = []string{
		`CREATE TRIGGER <<Table>>_uid10_bfr_insert BEFORE INSERT ON <<Table>> FOR EACH ROW
		IF NEW.uid IS NULL OR NEW.uid = '' THEN 
			SET @id = 1;
			WHILE (@id IS NOT NULL) DO
				SET NEW.uid = randstr(10);
				SET @id = (SELECT id FROM <<Table>> WHERE uid = NEW.uid);
			END WHILE;
		END IF;`,
	}

	// UID8
	behave[UID8{}] = []string{
		`CREATE TRIGGER <<Table>>_uid6_bfr_insert BEFORE INSERT ON <<Table>> FOR EACH ROW
			IF NEW.uid IS NULL OR NEW.uid = '' THEN 
				SET @id = 1;
				WHILE (@id IS NOT NULL) DO
					SET NEW.uid = randstr(8);
					SET @id = (SELECT id FROM <<Table>> WHERE uid = NEW.uid);
				END WHILE;
			END IF;`,
	}

	// SoftDelete
	behave[SoftDelete{}] = []string{
		// do not allow delete action
		`CREATE TRIGGER <<Table>>_softdelete_bfr_delete BEFORE DELETE ON <<Table>> FOR EACH ROW
		IF TRUE THEN 
			SIGNAL SQLSTATE '45000'
			SET MESSAGE_TEXT = 'Cannot delete records from table. Instead set deleted=1';
		END IF;`,
		// update deleted_at timestamp
		`CREATE TRIGGER <<Table>>_softdelete_bfr_update BEFORE UPDATE ON <<Table>> FOR EACH ROW
        BEGIN
            IF (OLD.deleted = 0) AND (NEW.deleted = 1) THEN
                SET NEW.deleted_at = NOW();
            END IF;
            IF (OLD.deleted = 1) AND (NEW.deleted = 0) THEN
                SET NEW.deleted_at = NULL;
            END IF;
        END`,
	}

	behave[Stateful{}] = []string{
		`CREATE TRIGGER <<Table>>_stateful_bfr_insert BEFORE INSERT ON <<Table>> FOR EACH ROW
        BEGIN
			DECLARE deft   VARCHAR(128);
			DECLARE entr   JSON;
			DECLARE sts    JSON;
			DECLARE fnd    INT;
			
			DECLARE tmpe   VARCHAR(512);
			DECLARE tmps   VARCHAR(512);
			DECLARE tmp    VARCHAR(128);

			# fetch state machine
			SELECT default_state, entry_states, states, count(1) INTO deft, entr, sts, fnd FROM state_machine WHERE entity = '<<Table>>'; 	

			SET tmpe = CAST(entr AS CHAR);
			SET tmps = CAST(sts AS CHAR);
			SET tmp = JSON_ARRAY(CAST(NEW.machine_state AS CHAR));

			IF NOT NEW.machine_state IS NULL THEN
				# state machine must exist
				IF fnd = 0 THEN
	            	SIGNAL SQLSTATE '45000'
   		           	SET MESSAGE_TEXT = 'State machine definition is missing';
   		        ELSE 
				   	# state must be part of start states
   		        	IF NOT entr IS NULL AND JSON_CONTAINS(tmpe, tmp,'$') = 0 THEN
	               		SIGNAL SQLSTATE '45000'
   		           		SET MESSAGE_TEXT = 'Invalid machine_state, should be one of entry_states';
					# state must be part of overall states array
   		           	ELSEIF JSON_CONTAINS(tmps, tmp, '$') = 0 THEN
               			SIGNAL SQLSTATE '45000'
	   	           		SET MESSAGE_TEXT = 'Invalid machine_state, should be one of states';
   		        	END IF;
				END IF;
			ELSEIF fnd = 1 THEN
				SET NEW.machine_state = deft;
			END IF;
            
			IF NOT NEW.machine_state IS NULL THEN
                SET NEW.stated_at = NOW();
            END IF;
		END`,
		`CREATE TRIGGER <<Table>>_stateful_bfr_update BEFORE UPDATE ON <<Table>> FOR EACH ROW
		BEGIN
			DECLARE deft   VARCHAR(128);
			DECLARE entr   JSON;
			DECLARE sts    JSON;
			DECLARE trns   JSON;
			DECLARE fnd    INT;

			DECLARE tmpe   VARCHAR(512);
			DECLARE tmps   VARCHAR(512);
			DECLARE tmpn   VARCHAR(128);
			DECLARE tmpt   VARCHAR(2048);
			
			# is a new state being set
			IF NOT NEW.machine_state IS NULL THEN 
			
				SELECT default_state, entry_states, states, transitions, count(1) INTO deft, entr, sts, trns, fnd FROM state_machine WHERE entity = '<<Table>>';

				SET tmpe = CAST(entr AS CHAR);
				SET tmps = CAST(sts AS CHAR);
				SET tmpt = CAST(trns AS CHAR);
				SET tmpn = JSON_ARRAY(CAST(NEW.machine_state AS CHAR));
				
				# state machine must be defined
				IF fnd = 0 THEN
					SIGNAL SQLSTATE '45000'
					SET MESSAGE_TEXT = 'State machine definition is missing';
				ELSE
				    # new state must be part of overall states
    				IF NOT sts IS NULL AND JSON_CONTAINS(tmps, tmpn, "$") = 0 THEN
					    SIGNAL SQLSTATE '45000'
					    SET MESSAGE_TEXT = 'New state is not a valid state definition';
				    END IF;

				END IF;

				IF OLD.machine_state IS NULL THEN
					# must be start state
					IF NOT entr IS NULL AND JSON_CONTAINS(tmpe, tmpn, "$") = 0 THEN
						SIGNAL SQLSTATE '45000'
						SET MESSAGE_TEXT = 'UPDATE must assign an entry state, as old state is NULL';
					END IF;
					SET NEW.stated_at = NOW();
				ELSEIF OLD.machine_state != NEW.machine_state THEN
					# must be valid transition
					IF NOT trns IS NULL AND JSON_CONTAINS(tmpt, JSON_OBJECT("from",OLD.machine_state, "to", NEW.machine_state))=0 THEN
						SIGNAL SQLSTATE '45000'
						SET MESSAGE_TEXT = 'No transition available from old state to new one';
					END IF;
					SET NEW.stated_at = NOW();
				#ELSE old-state == new-state, so do nuthin
				END IF;

			ELSE
						
			    IF NOT OLD.machine_state IS NULL THEN
					SIGNAL SQLSTATE '45000'
					SET MESSAGE_TEXT = 'UPDATE cannot set machine_state to NULL';
			    END IF;			
			
			END IF;

		END`,
		// push inserts into entities to state-queue
		`CREATE TRIGGER <<Table>>_stateful_aft_insert AFTER INSERT ON <<Table>> FOR EACH ROW
		BEGIN	
			IF NOT NEW.machine_state IS NULL THEN
				INSERT INTO state_machine_queue (entity,entity_id,created_at,updated_at,old_state,new_state) VALUES ('<<Table>>',NEW.ID,NEW.created_at,NEW.updated_at,'',NEW.machine_state);
			END IF;
		END`,
		// push updates of state machine to state-queue
		`CREATE TRIGGER <<Table>>_stateful_aft_update AFTER UPDATE ON <<Table>> FOR EACH ROW
		BEGIN	
			IF OLD.machine_state IS NULL AND NOT NEW.machine_state IS NULL THEN
				INSERT INTO state_machine_queue (entity,entity_id,created_at,updated_at,old_state,new_state) VALUES ('<<Table>>',NEW.ID,NEW.created_at,NEW.updated_at,'',NEW.machine_state);
			ELSEIF NOT OLD.machine_state IS NULL AND NOT NEW.machine_state IS NULL AND OLD.machine_state <> NEW.machine_state THEN
				INSERT INTO state_machine_queue (entity,entity_id,created_at,updated_at,old_state,new_state) VALUES ('<<Table>>',NEW.ID,NEW.created_at,NEW.updated_at,OLD.machine_state,NEW.machine_state);
			END IF;
        END`,
	}

}

func initDynamicBehaviors() {

	// Timed
	behaveModel[Timed{}] = func(model interface{}) []string {
		type Field struct {
			Name    string  `gorm:"column:Field"`
			Type    string  `gorm:"column:Type"`
			Null    string  `gorm:"column:Null"`
			Key     string  `gorm:"column:Key"`
			Default *string `gorm:"column:Default"`
			Extra   string  `gorm:"column:Extra"`
		}
		var f Field
		err := db().Raw("show columns from " + tableName(model) + " where Field = 'updated_at'").Find(&f).Error
		if err != nil {
			panic(err)
		}
		if !strings.Contains(strings.ToLower(f.Extra), "on update current_timestamp") {
			return []string{
				"ALTER TABLE <<Table>> MODIFY COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
			}
		}
		return []string{}
	}

	// SEO
	behaveModel[Seo{}] = func(model interface{}) []string {
		s := Seo{}
		return []string{
			`CREATE TRIGGER <<Table>>_seo_bfr_update BEFORE UPDATE ON <<Table>> FOR EACH ROW
			BEGIN
				IF NEW.url = '' THEN
					SIGNAL SQLSTATE '45000'
					SET MESSAGE_TEXT = '<<Table>>.Url cannot be updated to EMPTY';
				END IF;
				IF LEFT(NEW.url,1) <> '/' THEN
					SET NEW.url = CONCAT('/', NEW.url);
				END IF;
				IF (OLD.url <> '') AND (NEW.url <> OLD.url) THEN
					IF NEW.url_past IS NULL THEN
						SET NEW.url_past = JSON_ARRAY();
					END IF;
					IF JSON_CONTAINS(NEW.url_past, JSON_ARRAY(OLD.url)) = 0 THEN
						SET NEW.url_past = JSON_ARRAY_APPEND(NEW.url_past, "$", OLD.url);
					END IF;
				END IF;
			END`,
			fmt.Sprintf(`CREATE TRIGGER <<Table>>_seo_bfr_insert BEFORE INSERT ON <<Table>> FOR EACH ROW
				BEGIN
					DECLARE tmp VARCHAR(256);
					DECLARE count INT DEFAULT 0;
					DECLARE found INT DEFAULT 0;
		
					IF NEW.url = '' THEN
						SET tmp = geturl(NEW.%s);
						SET NEW.url = CONCAT('%s/', tmp);
					END IF;
					IF LEFT(NEW.url,1) <> '/' THEN
						SET NEW.url = CONCAT('/', NEW.url);
					END IF;
		
					SET found = (SELECT COUNT(*) FROM <<Table>> WHERE url = NEW.url);
					WHILE found > 0 DO
						SET count = count + 1;
						IF NOT EXISTS (SELECT * FROM <<Table>> WHERE url = CONCAT(NEW.url,count)) THEN
							SET NEW.url = CONCAT(NEW.url,count);
							SET found = 0;
						END IF;
					END WHILE;
				END`, s.UrlColumn(model), s.UrlPrefix(model)),
		}
	}

}