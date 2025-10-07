import { DateTime } from 'luxon';
import { EventEmitter } from 'events';

const ATTENDANCE_SHEET = 'Atendimentos CCA';

export class TaskManager extends EventEmitter {
  constructor({ sheetsService }) {
    super();
    this.sheetsService = sheetsService;
    this.tasks = new Map();
  }

  isTaskCompleted(task) {
    const status = (task?.status || '').toString().toLowerCase();
    return status.includes('concl');
  }

  async setSheetsService(sheetsService) {
    this.sheetsService = sheetsService;
    await this.refreshTasks();
  }

  async initialize() {
    await this.refreshTasks();
  }

  async refreshTasks() {
    const { rows } = await this.sheetsService.getRows(ATTENDANCE_SHEET);
    this.tasks.clear();
    rows.forEach((row, index) => {
      const [date, number, category, message, status, analyst] = row;
      const rowNumber = index + 2; // header occupies row 1
      this.tasks.set(rowNumber, {
        id: rowNumber,
        date,
        number,
        category,
        message,
        status,
        analyst
      });
    });
    const tasks = this.listTasks();
    this.emit('tasks:updated', {
      type: 'refresh',
      tasks
    });
    return tasks;
  }

  listTasks({ status } = {}) {
    let tasks = Array.from(this.tasks.values());
    if (status) {
      tasks = tasks.filter((task) => task.status === status);
    }
    return tasks;
  }

  async registerTask({ number, category, message, analyst }) {
    const date = DateTime.now().setZone('America/Sao_Paulo').toFormat('dd/MM/yyyy HH:mm');
    const status = 'Aberto';
    const response = await this.sheetsService.appendRow(ATTENDANCE_SHEET, [
      date,
      number,
      category,
      message,
      status,
      analyst ?? ''
    ]);

    const task = {
      id: response.rowNumber,
      date,
      number,
      category,
      message,
      status,
      analyst: analyst ?? ''
    };

    if (task.id) {
      this.tasks.set(task.id, task);
    }

    const tasks = this.listTasks();
    this.emit('tasks:updated', {
      type: 'created',
      task,
      tasks
    });

    return task;
  }

  async completeTask(id, { analyst }) {
    const task = this.tasks.get(id);
    if (!task) {
      throw new Error('Tarefa não encontrada');
    }

    const updated = { ...task, status: 'Concluído', analyst: analyst ?? task.analyst };
    await this.sheetsService.updateRow(ATTENDANCE_SHEET, id, [
      updated.date,
      updated.number,
      updated.category,
      updated.message,
      updated.status,
      updated.analyst
    ]);
    this.tasks.set(id, updated);

    const tasks = this.listTasks();
    this.emit('tasks:updated', {
      type: 'updated',
      task: updated,
      tasks
    });

    return updated;
  }

  async markAllAsRead() {
    let updatedCount = 0;
    const updatedTasks = [];

    for (const task of this.tasks.values()) {
      if (this.isTaskCompleted(task)) {
        continue;
      }
      const status = (task.status || '').toString().toLowerCase();
      if (status.includes('lido')) {
        continue;
      }

      const updated = { ...task, status: 'Lido' };
      await this.sheetsService.updateRow(ATTENDANCE_SHEET, task.id, [
        updated.date,
        updated.number,
        updated.category,
        updated.message,
        updated.status,
        updated.analyst
      ]);
      this.tasks.set(task.id, updated);
      updatedTasks.push(updated);
      updatedCount += 1;
    }

    const snapshot = this.listTasks();
    if (updatedCount) {
      this.emit('tasks:updated', {
        type: 'bulk-update',
        tasks: snapshot
      });
    }

    return {
      total: snapshot.length,
      updated: updatedCount,
      updatedTasks,
      tasks: snapshot
    };
  }

  async completeAllTasks({ analyst } = {}) {
    let updatedCount = 0;
    const updatedTasks = [];

    for (const task of this.tasks.values()) {
      if (this.isTaskCompleted(task)) {
        continue;
      }
      const updated = {
        ...task,
        status: 'Concluído',
        analyst: analyst ?? task.analyst
      };
      await this.sheetsService.updateRow(ATTENDANCE_SHEET, task.id, [
        updated.date,
        updated.number,
        updated.category,
        updated.message,
        updated.status,
        updated.analyst
      ]);
      this.tasks.set(task.id, updated);
      updatedTasks.push(updated);
      updatedCount += 1;
    }

    const snapshot = this.listTasks();
    if (updatedCount) {
      this.emit('tasks:updated', {
        type: 'bulk-update',
        tasks: snapshot
      });
    }

    return {
      total: snapshot.length,
      updated: updatedCount,
      updatedTasks,
      tasks: snapshot
    };
  }
}
